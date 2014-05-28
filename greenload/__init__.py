#!/usr/bin/env python
# coding: utf-8
"""
Loadtest for Web applications.
"""
from __future__ import print_function, division

__version__ = '0.4dev-gottani'

import gevent.pool
import geventhttpclient.client
from geventhttpclient.connectionpool import ConnectionPool

from collections import defaultdict
import logging
from optparse import OptionParser
import os
import re
import sys
import time
import urllib
import urlparse
import random
from gevent import socket
import zlib
import json


debug = logging.debug
info = logging.info
warn = logging.warn
error = logging.error

SUCC = FAIL = 0
STOP = False
PATH_TIME = PATH_CNT = None

PLUGINS = []

class AddressConnectionPool(ConnectionPool):
    addresses = []

    @classmethod
    def register_addresslist(cls, addresslist):
        for addr in addresslist:
            port = 80
            if ':' in addr:
                addr, port = addr.split(':')
                port = int(port)
            cls.addresses += socket.getaddrinfo(
                    addr, port,
                    socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP, 0)

    def _resolve(self):
        """returns (family, socktype, proto, cname, addr)"""
        if not self.addresses:
            self.addresses = ConnectionPool._resolve(self)
            for addr in self.addresses:
                debug("Resolved: %s", addr)
        random.shuffle(self.addresses)
        return self.addresses

geventhttpclient.client.ConnectionPool = AddressConnectionPool

MIMETYPE_FORM = 'application/x-www-form-urlencoded'
MIMETYPE_JSON = 'application/json'

"""
プラグインモジュールのimportを行います。
"""
def load_plugins(conf):
    import imp
    import traceback

    for p in conf.get('plugins', []):
        if p.get('file'):
            plugin_path = os.path.join(conf['BASEDIR'], p['file'])
            sys.path.append(os.path.dirname(plugin_path))
        try:
            (file, pathname, description) = imp.find_module(p['name'])
            PLUGINS.append(imp.load_module(p['name'], file, pathname, description))
        except Exception as ex:
            error("Failed to load plugin(%s)", p['name'])
            error(traceback.format_exc())

# 実行中に ... って表示する.
class Indicator(object):

    def __init__(self, skip=100):
        self.skip = skip
        self.c = 0

    def ok(self):
        self.c += 1
        if self.c >= self.skip:
            self.c = 0
            sys.stderr.write('.')

    def ng(self):
        sys.stderr.write('x')

_indicator = Indicator()
ok = _indicator.ok
ng = _indicator.ng
del _indicator


def load_conf(filename):
    basedir = os.path.dirname(filename)
    import yaml
    conf = yaml.load(open(filename))
    conf.setdefault('BASEDIR', basedir)

    if conf.get('actions'):
        # actionのloop展開
        def _pp_actions(actions, act):
            import copy
            if act.get('loop'):
                for i in range(0, act['loop']):
                    for subact in act['actions']:
                        _pp_actions(actions, subact)
            else:
                actions.append(copy.deepcopy(act))
        _actions = []
        for act in conf['actions']:
            _pp_actions(_actions, act)
        conf['actions'] = _actions

    return conf

def _load_vars(conf, name):
    if name not in conf:
        return {}
    V = {}
    basedir = conf['BASEDIR']
    for var in conf[name]:
        var_name = var['name']
        var_file = var['file']
        with open(os.path.join(basedir, var_file)) as f:
            V[var_name] = f.read().splitlines()
    return V

def load_vars(conf):
    u"""設定ファイルから3種類の変数を取得する.

    consts は、 Yaml に定義した name: value をそのまま使う.
    すべてのシナリオ実行で固定した値を用いる.

    vars は、 name の値として file 内の1行の文字列をランダムに選ぶ.
    1回のシナリオ実行中は固定

    exvars は、 vars と似ているが、並列して実行しているシナリオで
    重複しないように、値をラウンドロビンで選択する.

        consts:
            aaa: AAA
            bbb: BBB
        vars:
            -
                name: foo
                file: foo.txt
        exvars:
            -
                name: bar
                file: bar.txt
    """
    if 'consts' in conf:
        c = conf['consts']
    else:
        c = {}
    v = _load_vars(conf, 'vars')
    e = _load_vars(conf, 'exvars')
    return (c, v, e)


class VarEnv(object):
    u"""consts, vars, exvars から、1シナリオ用の変数セットを選択する
    コンテキストマネージャー.
    コンテキスト終了時に exvars を返却する.
    """
    def __init__(self, consts, vars_, ex):
        self.consts = consts
        self.all_vars = vars_
        self.all_exvars = ex

    def _select_vars(self):
        d = self.consts.copy()
        for k, v in self.all_vars.items():
            d[k] = random.choice(v)

        popped = {}
        for k, v in self.all_exvars.items():
            d[k] = popped[k] = v.get()
        self._popped = popped
        return d

    def __enter__(self):
        return self._select_vars()

    def __exit__(self, *err):
        for k, v in self._popped.items():
            self.all_exvars[k].put(v)


class Action(object):
    def __init__(self, conf, action):
        self.conf = conf
        self.action = action
        self.method = action.get('method', 'GET')
        self.path = action['path']
        self.path_name = action.get('path_name')
        #: 全リクエストに付与するクエリー文字列
        self.query_params = conf.get('query_params', {}).items()
        self.headers = conf.get('headers', {})
        self.content = action.get('content')
        self.content_type = action.get('content_type')

        # 全リクエストに付与するPOSTパラメータ
        self.post_params = None
        if conf.get('post_params'):
            self.post_params = conf.get('post_params').copy()
        if action.get('post_params'):
            if self.post_params:
                self.post_params.update( action.get('post_params'))
            else:
                self.post_params = action.get('post_params')

        # 正規表現による変数キャプチャ
        if action.get('scan'):
            self._scan_r = []
            for (k, v) in action.get('scan').items():
                self._scan_r.append((k, re.compile(v)))
        else:
            self._scan_r = None

        # JSONからの変数キャプチャ
        if action.get('scan_jsons'):
            self.scan_jsons = action.get('scan_jsons').items()
        else:
            self.scan_jsons = None

        # アクションのガード条件
        if action.get('condition'):
            self.condition = action.get('condition')
        else:
            self.condition = None

        # 変数生成定義
        if action.get('setvars'):
            self.setvars = action.get('setvars').items()
        else:
            self.setvars = None

        # アサーション定義
        if action.get('assertions'):
            self.assertions = action.get('assertions').items()
        else:
            self.assertions = None

    # 指定された正規表現で変数キャプチャする
    def _scan(self, response_body, vars_):
        if not self._scan_r:
            return
        for (k, v) in self._scan_r:
            m = v.search(response_body)
            if m:
                vars_[k] = m.group(1)
                info("success in scan(%s) = %s", k, vars_[k])
            else:
                info("failed to regexp scan(%s)", k)

    # 指定されたキー定義で変数キャプチャする
    def _scan_jsons(self, response_body, vars_):
        if not self.scan_jsons:
            return
        vars_['json'] = json.loads(response_body)
        for (k, v) in self.scan_jsons:
            try:
                vars_[k] = self._replace_names(v, vars_, True)
                info("success in scan_jsons(%s) = %s", k, str(vars_[k])[:100])
            except Exception as ex:
                info("failed to eval scan_jsons(%s): %s", k, ex)
        vars_['json'] = None

    # 新しい変数の作成
    def _setvars(self, vars_):
        if not self.setvars:
            return
        for (k, v) in self.setvars:
            try:
                vars_[k] = self._replace_names(v, vars_, True)
                info("success in setvars(%s) = %s", k, vars_[k])
            except Exception as ex:
                info("failed to eval setvars(%s): %s", k, ex)

    # 処理結果の最終アサーション
    def _assertion(self, vars_):
        if not self.assertions:
            return False
        for (k, v) in self.assertions:
            try:
                if self._replace_names(v, vars_, True):
                    info("success in assertion(%s)", k)
                    return False
                else:
                    info("error in assertion(%s)", k)
                    return True
            except Exception as ex:
                info("failed to eval assertion(%s): %s", k, ex)
                return True

    # アクションの実行ガード条件チェック
    def _check_condition_torun(self, vars_):
        if not self.condition:
            return True
        if not self._replace_names(self.condition, vars_, True):
            info("condition(" + self.condition + ") is false, skip.")
            return False
        else:
            info("condition(" + self.condition + ") is true")
            return True

    # "%(..)%"があった場合はevalによる実行時置換を行う。forceの場合は無条件でevalする。
    def _replace_names(self, s, v, force=False, _sub_name=re.compile('%\((.+?)\)%').subn):
        (s2, subs) = _sub_name(lambda m: "v.get('%s')" % (m.group(1)), s)
        if subs or force:
            try:
                return eval(s2)
            except SyntaxError:
                warn("Syntax error found: %s", s)
                return s
        else:
            return s

    def execute(self, client, vars_):
        info("execute self.path =====>> %s", self.path)

        for p in PLUGINS:
            p.pre_action(self, client, vars_)

        if not self._check_condition_torun(vars_):
            return True

        u"""1アクションの実行

        リダイレクトを処理するのでリクエストは複数回実行する
        """
        method = self.method
        #: path - 変数展開前のURL
        #: この path ごとに集計を行う.
        path = self.path
        #: path_name がついている場合はそれを別名として使う
        if self.path_name:
            path = self.path_name
        query_params = [(k, self._replace_names(v, vars_))
                        for (k, v) in self.query_params]
        header = self.headers.copy()
        for k in header:
            header[k] = self._replace_names(header[k], vars_)

        #: realpath - 変数展開した実際にアクセスするURL
        real_path = self._replace_names(self.path, vars_)

        if method == 'POST' and self.content is not None:
            body = self._replace_names(self.content, vars_)
            header['Content-Type'] = self._replace_names(self.content_type, vars_)
        elif method == 'POST' and self.post_params is not None:
            post_params = [(k, self._replace_names(v, vars_))
                           for (k, v) in self.post_params.items()]
            body = urllib.urlencode(post_params)
            header['Content-Type'] = 'application/x-www-form-urlencoded'
        else:
            body = b''

        while 1:  # リダイレクトループ
            if query_params:
                if '?' in real_path:
                    p1, p2 = real_path.split('?')
                    p2 = urlparse.parse_qsl(p2) + query_params
                else:
                    p1 = real_path
                    p2 = query_params
                p2 = urllib.urlencode(p2)
                real_path = p1 + '?' + p2

            cookies = vars_.setdefault('__cookies__', {})
            if cookies:
                header['Cookie'] = '; '.join([h + '=' + v for h, v in cookies.items()])

            debug("%s %s %s", method, real_path, body[:20])
            t = time.time()
            try:
                timeout = False
                response = None
                response = client.request(method, real_path, body, header)
                response_body = response.read()
            except (gevent.timeout, gevent.socket.timeout):
                timeout = True
                response = None
                break
            except IOError as e:
                response = None
                err = e
                break
            finally:
                # t はエラー時も使われるので常に計測する.
                t = time.time() - t
                if response is not None:
                    for response_header, response_header_val in response.items():
                        if response_header == 'set-cookie':
                            name, val = response_header_val.split(';')[0].strip().split('=')
                            cookies[name] = val

            PATH_TIME[path] += t
            PATH_CNT[path] += 1

            if response.status_code // 10 != 30:  # isn't redirect
                break

            # handle redirects.
            debug("(%.2f[ms]) %s location=%s", t*1000,
                  response.status_code, response['location'])
            method = 'GET'
            body = b''
            headers = self.headers
            frag = urlparse.urlparse(response['location'])
            if frag.query:
                path = real_path = '%s?%s' % (frag.path, frag.query)
            else:
                path = real_path = frag.path

        if response and response.get('content-encoding') == 'gzip':
            info('Content-Encoding: gzip')
            response_body = zlib.decompress(response_body, 16+zlib.MAX_WBITS)

        has_assert_error = False

        if timeout:
            succ = False
        elif not response:
            succ = False
        elif not response.status_code // 10 == 20:
            succ = False
        else:
            succ = True
            if response['content-type'].startswith(MIMETYPE_JSON):
                self._scan_jsons(response_body, vars_)
            else:
                self._scan(response_body, vars_)
            self._setvars(vars_)
            if self._assertion(vars_):
                has_assert_error = True
                succ = False

        for p in reversed(PLUGINS):
            succ = p.post_action(self, client, vars_, response, succ)

        if succ:
            global SUCC
            SUCC += 1
            ok()
            debug("(%.2f[ms]) %s %s",
                  t*1000, response.status_code, response_body[:100])
            return True
        else:
            global FAIL
            FAIL += 1
            ng()
            if response:
                if has_assert_error:
                    warn("\nassert: time=%.2f[ms] path=%s", t*1000, path)
                else:
                    warn("(%.2f[ms]) %s %s",
                         t*1000, response.status_code, response_body)
            elif timeout:
                warn("\ntimeout: time=%.2f[sec] url=%s", t, path)
            else:
                error("time=%.2f[sec] url=%s error=%s", t, path, err)
            return False


def run_actions(client, conf, vars_, actions):
    succ = True
    for action in actions:
        if STOP or not succ:
            break
        succ = action.execute(client, vars_)


def hakai(client, conf, VARS):
    global LOOP
    actions = [Action(conf, a) for a in conf['actions']]
    VARS = VarEnv(*VARS)

    while True:
        if STOP:
            break
        LOOP -= 1
        if LOOP < 0:
            break
        with VARS as vars_:
            run_actions(client, conf, vars_, actions)


def make_exvars(ex):
    d = {}
    for k, v in ex.items():
        d[k] = gevent.queue.Queue(None, v)
    return d


def make_parser():
    parser = OptionParser(usage="%prog [options] config.yml ...")
    parser.add_option('-f', '--fork', type='int')
    parser.add_option('-c', '--max-request', type='int')
    parser.add_option('-n', '--loop', type='int')
    parser.add_option('-d', '--total-duration', type='float')
    parser.add_option('-s', '--max-scenario', type='int')
    parser.add_option('-v', '--verbose', action="count", default=0)
    parser.add_option('-q', '--quiet', action="count", default=0)
    return parser


def update_conf(conf, opts):
    u"""設定ファイルの内容をコマンドラインオプションで上書きする"""
    conf['max_scenario'] = int(opts.max_scenario or
                               conf.get('max_scenario', 1))
    conf['max_request'] = int(opts.max_request or
                              conf.get('max_request', conf['max_scenario']))
    conf['loop'] = int(opts.loop or conf.get('loop', 1))
    conf['total_duration'] = opts.total_duration or conf.get('total_duration')

    loglevel = conf.get("log_level", 3)
    loglevel += opts.quiet - opts.verbose
    loglevel = max(loglevel, 1)
    conf['log_level'] = loglevel

def run_hakai(conf, all_vars):
    u"""各プロセスで動くmain関数"""
    global SUCC, FAIL, PATH_TIME, PATH_CNT, STOP, LOOP
    SUCC = 0
    FAIL = 0
    LOOP = conf['loop'] * conf['max_scenario']
    STOP = False
    PATH_TIME = defaultdict(int)
    PATH_CNT = defaultdict(int)

    load_plugins(conf)
    logging.getLogger().setLevel(conf['log_level'] * 10)

    addresslist = conf.get('addresslist')
    if addresslist:
        AddressConnectionPool.register_addresslist(addresslist)

    host = conf['domain']
    user_agent = conf.get('user_agent', 'green hakai/0.1')
    timeout = float(conf.get('timeout', 10))
    client = geventhttpclient.HTTPClient.from_url(
            host,
            concurrency=conf['max_request'],
            connection_timeout=timeout,
            network_timeout=timeout,
            headers={'User-Agent': user_agent},
            )

    vars_ = all_vars[0], all_vars[1], make_exvars(all_vars[2])

    group = gevent.pool.Group()
    for _ in xrange(conf['max_scenario']):
        group.spawn(hakai, client, conf, vars_)
    group.join(conf['total_duration'])
    STOP = True
    group.kill()
    return SUCC, FAIL, dict(PATH_TIME), dict(PATH_CNT)


def remote_main(channel):
    u"""run_hakai() をリモートで動かすエージェント"""
    conf, vars_ = channel.receive()
    result = run_hakai(conf, vars_)
    channel.send(result)


def build_specs(conf, opts):
    u"""conf, opts から execnet 用の spec を作る"""
    if opts.fork:
        return ['popen'] * opts.fork
    nodes = conf.get('nodes')
    if not nodes:
        return ['popen'] * conf.get('fork', 1)

    specs = []
    for node in nodes:
        host = node['host']
        if host == 'localhost':
            s = 'popen'
        else:
            # リモートの Python も同じ場所に有ることを仮定する
            s = "ssh=" + host + "//python=" + sys.executable
        specs += [s] * node['proc']

    return specs


def main():
    parser = make_parser()
    opts, args = parser.parse_args()
    if not args:
        parser.print_help()
        return

    conf = {}
    for arg in args:
        conf.update(load_conf(arg))
    update_conf(conf, opts)

    logging.getLogger().setLevel(conf['log_level'] * 10)

    specs = build_specs(conf, opts)
    procs = len(specs)

    if specs == ['popen']:
        # ローカル1プロセスの場合は直接実行する.
        now = time.time()
        SUCC, FAIL, PATH_TIME, PATH_CNT = run_hakai(conf, load_vars(conf))
        delta = time.time() - now
    else:
        import execnet
        import greenload
        group = execnet.Group(specs)
        multi_chan = group.remote_exec(greenload)

        all_vars = []
        consts, vars_, exvars = load_vars(conf)
        for i in xrange(procs):
            ie = {}
            for k, v in exvars.items():
                ie[k] = v[i::procs]
            all_vars.append((consts, vars_, ie))

        now = time.time()
        for v, ch in zip(all_vars, multi_chan):
            ch.send((conf, v))
        results = multi_chan.receive_each()
        delta = time.time() - now

        SUCC = 0
        FAIL = 0
        PATH_TIME = defaultdict(int)
        PATH_CNT = defaultdict(int)
        for succ, fail, path_time, path_cnt in results:
            SUCC += succ
            FAIL += fail
            for k, v in path_time.items():
                PATH_TIME[k] += v
            for k, v in path_cnt.items():
                PATH_CNT[k] += v

    print()
    NREQ = SUCC + FAIL
    req_per_sec = NREQ / delta
    print("request count:%d, concurrency:%d, time:%f, %f req/s" %
          (NREQ, conf['max_request'] * procs, delta, req_per_sec))
    print("SUCCESS", SUCC)
    print("FAILED", FAIL)

    total_cnt = total_time = 0

    avg_time_by_path = []
    for path, cnt in PATH_CNT.iteritems():
        t = PATH_TIME[path]
        avg_time_by_path.append((t/cnt, path))
        total_cnt += cnt
        total_time += t

    print("Average response time[ms]:", 1000*total_time/total_cnt if total_cnt else '-')
    if conf.get('show_report'):
        ranking = int(conf.get('ranking', 20))
        print("Average response time for each path (order by longest) [ms]:")
        avg_time_by_path.sort(reverse=True)
        for t, p in avg_time_by_path[:ranking]:
            print(t*1000, p)


if __name__ == '__main__':
    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s")
    main()

elif __name__ == '__channelexec__':
    # execnet 経由で実行される場合.
    remote_main(channel)
