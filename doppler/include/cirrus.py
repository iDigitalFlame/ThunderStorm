#!/usr/bin/python3

from include.util import nes
from requests import session
from genericpath import exists
from include.config import Config
from websocket import WebSocketApp
from threading import Thread, Event
from base64 import b64decode, b64encode
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE
from os.path import expanduser, expandvars, isfile

REG_TYPES = [
    "sz",
    "string",
    "bin",
    "binary",
    "uint32",
    "dword",
    "uint64",
    "qword",
    "multi",
    "multi_sz",
    "exp_sz",
    "expand_string",
]
EXEC_TYPES = ["", "dll", "asm", "exec", "pexec", "zombie"]
REG_ACTIONS = ["delete", "del", "rm", "rem", "remove", "ls", "get", "dir"]


def _is_config(c):
    return isinstance(c, Config) or isinstance(c, bytearray) or isinstance(c, bytes)


def split_dll(p, f):
    if f[0] == "!":
        v = expanduser(expandvars(f[1:]))
        if not isfile(v):
            raise ValueError(f'file "{v}" does not exist')
        with open(v, "rb") as f:
            p["data"] = b64encode(f.read()).decode("UTF-8")
        del v
        return
    v = expanduser(expandvars(f))
    if not isfile(v):
        p["path"] = f
        return
    with open(v, "rb") as f:
        p["data"] = b64encode(f.read()).decode("UTF-8")
    del v


def _err_from_stat(r, url, ex):
    if r.status_code == ex:
        return
    try:
        d = r.json()
        r.close()
    except Exception:
        raise ValueError(f'"{url}" returned non-{ex} status: {r.status_code}')
    if not isinstance(d, dict) or len(d) == 0 or not nes(d.get("error")):
        raise ValueError(f'"{url}" returned non-{ex} status: {r.status_code}')
    raise CirrusError(
        f'"{url}" returned non-{ex} status: ({r.status_code}) {d["error"]}',
        sub=d["error"],
    )


def _create_spawn(name, method, profile, exec, show, filter):
    if not nes(name):
        raise ValueError('"name" must be a non-empty string')
    if nes(method) and exec is None:
        raise ValueError('"exec" cannot be None when "method" is set')
    if filter is not None and not isinstance(filter, Filter):
        raise ValueError('"filter" must be a Filter type')
    e = exec
    if exec is not None and not isinstance(exec, dict):
        if not nes(exec):
            raise ValueError('cannot guess empty/non-string "exec" value')
        if not nes(method):
            if exec.lower().startswith("http") and "://" in exec:
                method, e = "pexec", exec
            else:
                method, e = "exec", {"show": show, "cmd": exec}
        elif method.lower() == "exec":
            e = {"show": show, "cmd": exec}
        elif method.lower() == "pexec":
            e = exec
        else:
            raise ValueError('"method" value is not valid for string "exec" type')
    if not isinstance(method, str):
        v = ""
    else:
        v = method.lower()
    if v not in EXEC_TYPES:
        raise ValueError('"method" value is not a valid type')
    p = {"name": name, "method": v}
    del v
    if e is not None:
        p["payload"] = e
    del e
    if nes(profile):
        p["profile"] = profile
    if isinstance(filter, Filter):
        p["filter"] = filter.json()
    return p


class Api(object):
    def __init__(self, base_url, password=None):
        if not nes(base_url):
            return ValueError('"base_url" must be a non-empty string')
        if base_url.startswith("http"):
            if base_url[5] == ":":
                i = 8
            else:
                i = 7
            self._host = base_url[i:].rstrip("/")
            del i
        else:
            self._host = base_url.rstrip("/")
        if base_url[4] == "s":
            self._base = f"https://{self._host}/api/v1"
            self._ws = WebSocketApp(f"wss://{self._host}/api/v1/events")
        else:
            self._base = f"http://{self._host}/api/v1"
            self._ws = WebSocketApp(f"ws://{self._host}/api/v1/events")
        self._s = session()
        if nes(password):
            self._s.headers["X-CirrusAuth"] = password
            self._ws.header = {"X-CirrusAuth": password}

    def close(self):
        if self._events is None:
            return
        self._events.close()

    def _detect_open(self, _):
        try:
            self._trigger.set()
        except AttributeError:
            pass

    def _req(self, url, exp, method, data=None, json=None):
        if not nes(method):
            raise ValueError("invalid method")
        try:
            f = getattr(self._s, method)
        except AttributeError:
            raise ValueError(f'unsupported method: "{method}"')
        if not callable(f):
            raise ValueError(f'invalid method: "{method}"')
        if json:
            r = f(f"{self._base}/{url}", json=json)
        else:
            r = f(f"{self._base}/{url}", data=data)
        if isinstance(exp, list) and r.status_code not in exp:
            _err_from_stat(r, f"{self._base}/{url}", "|".join([str(e) for e in exp]))
        if isinstance(exp, int):
            if exp == -1:
                return r
            _err_from_stat(r, f"{self._base}/{url}", exp)
        if r.content is None or len(r.content) == 0:
            r.close()
            del r
            return None
        if isinstance(json, bool) and not json:
            d = r.content
            r.close()
            del r
            return d
        d = r.json()
        r.close()
        del r
        return d

    def start_events(self, on_msg, on_close=None):
        self._ws.on_close = on_close
        self._ws.on_message = on_msg
        self._events = _Events(self._ws)
        self._trigger = Event()
        self._ws.on_open = self._detect_open
        self._events.start()
        try:
            if self._trigger.wait(2):
                return
            self._ws.close()
            raise RuntimeError(f'Timeout connecting to "{self._ws.url}"')
        finally:
            del self._trigger

    def jobs(self, id):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        return self._req(f"session/{id}/job", 200, "get")

    def job(self, id, job):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not isinstance(job, int) or job < 1 or job > 0xFFFF:
            raise ValueError('"job" must be a positive number between [1-65535]')
        return self._req(f"session/{id}/job/{job}", 200, "get")

    def job_delete(self, id, job):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not isinstance(job, int) or job < 1 or job > 0xFFFF:
            raise ValueError('"job" must be a positive number between [1-65535]')
        return self._req(f"session/{id}/job/{job}", 200, "delete")

    def job_result(self, id, job, delete=False):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not isinstance(job, int) or job <= 0 or job > 0xFFFF:
            raise ValueError('"job" must be a positive number between [1-65535]')
        r = self._req(
            f"session/{id}/job/{job}/result", -1, "delete" if delete else "get"
        )
        if r.status_code == 404 or r.status_code == 500:
            _err_from_stat(r, f"{self._base}/session/{id}/job/{job}/result", "200X")
        if r.status_code == 425:
            return False
        if r.status_code == 204:
            return None
        d = r.json()
        r.close()
        if r.status_code == 206:
            if "error" not in d:
                raise ValueError(
                    f'"{self._base}/session/{id}/job/{job}/result" returned an invalid result'
                )
        del r
        return d

    def profiles(self):
        r = dict()
        for k, v in self._req("profile", 200, "get").items():
            r[k] = Config(b64decode(v, validate=True))
        return dict(sorted(r.items()))

    def profile(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        return Config(
            b64decode(
                self._req(f"profile/{name}", 200, "get", json=False), validate=True
            )
        )

    def profile_delete(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        return self._req(f"profile/{name}", 200, "delete")

    def profile_add(self, name, config):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not _is_config(config):
            raise ValueError('"config" must be a Config, bytearray or bytes type')
        r = self._req(f"profile/{name}", 201, "put", b64encode(config))
        if not isinstance(r, dict):
            raise ValueError(f'"{self._base}/profile/{name}" returned invalid data')
        return r

    def profile_update(self, name, config):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not _is_config(config):
            raise ValueError('"config" must be a Config, bytearray or bytes type')
        r = self._req(f"profile/{name}", 200, "post", b64encode(config))
        if not isinstance(r, dict):
            raise ValueError(f'"{self._base}/profile/{name}" returned invalid data')
        return r

    def sessions(self):
        v = self._req("session", 200, "get")
        v.sort(key=lambda x: x["id"], reverse=True)
        return v

    def session(self, id):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        return self._req(f"session/{id}", 200, "get")

    def session_proxy_delete(self, id, name):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not isinstance(name, str):
            raise ValueError('"name" must be a string')
        r = self._req(
            f"session/{id}/proxy/{name}",
            200,
            "delete",
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/proxy/{name}" returned an invalid result'
            )
        return int(r["id"])

    def session_remove(self, id, shutdown=False):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        return self._req(f"session/{id}", 200, "delete", json={"shutdown": shutdown})

    def session_proxy_add(self, id, name, address, profile):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(address):
            raise ValueError('"address" must be a non-empty string')
        if not nes(profile):
            raise ValueError('"profile" must be a non-empty string')
        if not isinstance(name, str):
            raise ValueError('"name" must be a string')
        r = self._req(
            f"session/{id}/proxy/{name}",
            201,
            "put",
            json={"address": address, "profile": profile},
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/proxy/{name}" returned an invalid result'
            )
        return int(r["id"])

    def session_proxy_update(self, id, name, address, profile):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(address):
            raise ValueError('"address" must be a non-empty string')
        if not nes(profile):
            raise ValueError('"profile" must be a non-empty string')
        if not isinstance(name, str):
            raise ValueError('"name" must be a string')
        r = self._req(
            f"session/{id}/proxy/{name}",
            200,
            "post",
            json={"address": address, "profile": profile},
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/proxy/{name}" returned an invalid result'
            )
        return int(r["id"])

    def listeners(self):
        r = self._req("listener", 200, "get")
        if not isinstance(r, dict) or len(r) == 0:
            return dict()
        return dict(sorted(r.items()))

    def listener(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        return self._req(f"listener/{name}", 200, "get")

    def listener_delete(self, name):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        return self._req(f"listener/{name}", 200, "delete")

    def listener_add(self, name, address, profile):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(profile):
            raise ValueError('"profile" must be a non-empty string')
        return self._req(
            f"listener/{name}",
            201,
            "put",
            json={"profile": profile, "address": address},
        )

    def listener_update(self, name, address, profile):
        if not nes(name):
            raise ValueError('"name" must be a non-empty string')
        if not nes(profile):
            raise ValueError('"profile" must be a non-empty string')
        return self._req(
            f"listener/{name}",
            200,
            "post",
            json={"profile": profile, "address": address},
        )

    def task_io_touch(self, id, path):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(path):
            raise ValueError('"path" must be a non-empty string')
        r = self._req(
            f"session/{id}/io", 201, "put", json={"action": "touch", "path": path}
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/io" returned an invalid result'
            )
        return int(r["id"])

    def task_pull(self, id, url, dest):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(url):
            raise ValueError('"url" must be a non-empty string')
        if not nes(dest):
            raise ValueError('"dest" must be a non-empty string')
        r = self._req(f"session/{id}/pull", 201, "put", json={"path": dest, "url": url})
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/pull" returned an invalid result'
            )
        return int(r["id"])

    def task_profile(self, id, profile):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(profile):
            raise ValueError('"profile" must be a non-empty string')
        r = self._req(f"session/{id}/profile", 201, "put", json={"profile": profile})
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/profile" returned an invalid result'
            )
        return int(r["id"])

    def task_download(self, id, target):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(target):
            raise ValueError('"target" must be a non-empty string')
        r = self._req(f"session/{id}/download", 201, "put", json={"path": target})
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/download" returned an invalid result'
            )
        return int(r["id"])

    def task_io_copy(self, id, src, dst):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(src):
            raise ValueError('"src" must be a non-empty string')
        if not nes(dst):
            raise ValueError('"dest" must be a non-empty string')
        r = self._req(
            f"session/{id}/io",
            201,
            "put",
            json={"action": "copy", "source": src, "dest": dst},
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/io" returned an invalid result'
            )
        return int(r["id"])

    def task_io_move(self, id, src, dst):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(src):
            raise ValueError('"src" must be a non-empty string')
        if not nes(dst):
            raise ValueError('"dest" must be a non-empty string')
        r = self._req(
            f"session/{id}/io",
            201,
            "put",
            json={"action": "move", "source": src, "dest": dst},
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/io" returned an invalid result'
            )
        return int(r["id"])

    def task_system(self, id, cmd, filter=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(cmd):
            raise ValueError('"cmd" must be a non-empty string')
        if filter is not None and not isinstance(filter, Filter):
            raise ValueError('"filter" must be a Filter type')
        if " " in cmd:
            v = cmd.find(" ")
            p = {"cmd": cmd[:v], "args": cmd[v + 1 :]}
            del v
        else:
            p = {"cmd": cmd}
        if isinstance(filter, Filter):
            p["filter"] = filter.json()
        try:
            r = self._req(f"session/{id}/sys", [200, 201], "put", json=p)
        finally:
            del p
        if r is None:
            return None
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/sys" returned an invalid result'
            )
        return int(r["id"])

    def task_io_delete(self, id, path, force=False):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(path):
            raise ValueError('"path" must be a non-empty string')
        r = self._req(
            f"session/{id}/io",
            201,
            "put",
            json={"action": "delete", "path": path, "force": force},
        )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/io" returned an invalid result'
            )
        return int(r["id"])

    def task_io_kill(self, id, pid=None, name=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if (not isinstance(pid, int) or pid <= 0) and not nes(name):
            raise ValueError('"pid" or "name" must be specified')
        if isinstance(pid, int) and pid > 0:
            r = self._req(
                f"session/{id}/io",
                201,
                "put",
                json={"action": "kill", "pid": pid},
            )
        else:
            r = self._req(
                f"session/{id}/io",
                201,
                "put",
                json={"action": "kill_name", "name": name},
            )
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/io" returned an invalid result'
            )
        return int(r["id"])

    def task_upload(self, id, target, dest, raw=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(dest):
            raise ValueError('"dest" must be a non-empty string')
        if not isinstance(raw, bytes) and not isinstance(raw, bytearray):
            if not nes(target):
                raise ValueError('"target" must be a non-empty string')
            p = expanduser(expandvars(target))
            if not exists(p):
                raise ValueError(f'target "{p}" does not exist')
            with open(p, "rb") as f:
                b = b64encode(f.read()).decode("UTF-8")
            del p
        else:
            b = b64encode(raw).decode("UTF-8")
        try:
            r = self._req(
                f"session/{id}/upload", 201, "put", json={"path": dest, "data": b}
            )
        finally:
            del b
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/upload" returned an invalid result'
            )
        return int(r["id"])

    def task_execute(self, id, cmd, show=False, detach=False, filter=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(cmd):
            raise ValueError('"cmd" must be a non-empty string')
        if filter is not None and not isinstance(filter, Filter):
            raise ValueError('"filter" must be a Filter type')
        p = {"cmd": cmd, "show": show, "detach": detach}
        if isinstance(filter, Filter):
            p["filter"] = filter.json()
        try:
            r = self._req(f"session/{id}/exec", 201, "put", json=p)
        finally:
            del p
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/exec" returned an invalid result'
            )
        return int(r["id"])

    def task_pull_exec(self, id, url, show=False, detach=False, filter=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(url):
            raise ValueError('"url" must be a non-empty string')
        if filter is not None and not isinstance(filter, Filter):
            raise ValueError('"filter" must be a Filter type')
        p = {"url": url, "show": show, "detach": detach}
        if isinstance(filter, Filter):
            p["filter"] = filter.json()
        try:
            r = self._req(f"session/{id}/pexec", 201, "put", json=p)
        finally:
            del p
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/pexec" returned an invalid result'
            )
        return int(r["id"])

    def task_assembly(self, id, file, raw=None, show=False, detach=False, filter=None):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if filter is not None and not isinstance(filter, Filter):
            raise ValueError('"filter" must be a Filter type')
        if not isinstance(raw, bytes) and not isinstance(raw, bytearray):
            if not nes(file):
                raise ValueError('"file" must be a non-empty string')
            p = expanduser(expandvars(file))
            if not exists(p):
                raise ValueError(f'file "{p}" does not exist')
            with open(p, "rb") as f:
                b = b64encode(f.read()).decode("UTF-8")
            del p
        else:
            b = b64encode(raw).decode("UTF-8")
        p = {"show": show, "detach": detach, "data": b}
        del b
        if isinstance(filter, Filter):
            p["filter"] = filter.json()
        try:
            r = self._req(f"session/{id}/asm", 201, "put", json=p)
        finally:
            del p
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/asm" returned an invalid result'
            )
        return int(r["id"])

    def task_dll(
        self, id, file, raw=None, reflect=True, show=False, detach=False, filter=None
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if filter is not None and not isinstance(filter, Filter):
            raise ValueError('"filter" must be a Filter type')
        p = {"show": show, "detach": detach, "reflect": reflect}
        if not isinstance(raw, bytes) and not isinstance(raw, bytearray):
            if not nes(file):
                raise ValueError('"file" must be a non-empty string')
            split_dll(p, file)
        else:
            p["data"] = b64encode(raw).decode("UTF-8")
        if isinstance(filter, Filter):
            p["filter"] = filter.json()
        try:
            r = self._req(f"session/{id}/dll", 201, "put", json=p)
        finally:
            del p
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/dll" returned an invalid result'
            )
        return int(r["id"])

    def task_spawn(
        self,
        id,
        name,
        method=None,
        profile=None,
        exec=None,
        show=False,
        filter=None,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        p = _create_spawn(name, method, profile, exec, show, filter)
        try:
            r = self._req(f"session/{id}/sys/spawn", 201, "put", json=p)
        finally:
            del p
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/sys/spawn" returned an invalid result'
            )
        return int(r["id"])

    def task_zombie(
        self,
        id,
        file,
        fake_args,
        raw=None,
        show=False,
        detach=False,
        filter=None,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(fake_args):
            raise ValueError('"fake_args" must be a non-empty string')
        if filter is not None and not isinstance(filter, Filter):
            raise ValueError('"filter" must be a Filter type')
        if not isinstance(raw, bytes) and not isinstance(raw, bytearray):
            if not nes(file):
                raise ValueError('"file" must be a non-empty string')
            p = expanduser(expandvars(file))
            if not exists(p):
                raise ValueError(f'file "{p}" does not exist')
            with open(p, "rb") as f:
                b = b64encode(f.read()).decode("UTF-8")
            del p
        else:
            b = b64encode(raw).decode("UTF-8")
        p = {"show": show, "detach": detach, "data": b, "fake": fake_args}
        del b
        if isinstance(filter, Filter):
            p["filter"] = filter.json()
        try:
            r = self._req(f"session/{id}/zombie", 201, "put", json=p)
        finally:
            del p
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/zombie" returned an invalid result'
            )
        return int(r["id"])

    def task_migrate(
        self,
        id,
        name,
        method=None,
        profile=None,
        exec=None,
        show=False,
        filter=None,
        wait=True,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')

        p = _create_spawn(name, method, profile, exec, show, filter)
        p["wait"] = wait
        try:
            r = self._req(f"session/{id}/sys/migrate", 201, "put", json=p)
        finally:
            del p
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/sys/migrate" returned an invalid result'
            )
        return int(r["id"])

    def task_registry(
        self,
        id,
        action,
        key,
        value=None,
        type=None,
        data=None,
        force=False,
    ):
        if not nes(id):
            raise ValueError('"id" must be a non-empty string')
        if not nes(key):
            raise ValueError('"key" must be a non-empty string')
        if not nes(action):
            raise ValueError('"action" must be a non-empty string')
        a = action.lower()
        if a == "get" and not nes(value):
            raise ValueError('"value" must be a non-empty string for a get action')
        elif a == "set" or a == "edit" or a == "update":
            if not nes(value):
                raise ValueError('"value" must be a non-empty string for a set action')
            if not nes(type):
                raise ValueError('"type" must be a non-empty string for a set action')
            if type.lower() not in REG_TYPES:
                raise ValueError(f'type "{type}" is not valid')
        elif a not in REG_ACTIONS:
            raise ValueError(f'action "{action}" is not valid')
        p = {"key": key, "force": force, "action": a}
        if a == "set" or a == "edit" or a == "update":
            if data is not None:
                if isinstance(data, bytes) or isinstance(data, bytearray):
                    p["data"] = b64encode(data).decode("UTF-8")
                elif isinstance(data, int) or isinstance(data, float):
                    p["data"] = str(data)
                elif not isinstance(data, str):
                    raise ValueError('"data" type is not valid')
                else:
                    p["data"] = data
            p["type"] = type
        if nes(value):
            p["value"] = value
        del a
        try:
            r = self._req(f"session/{id}/regedit", 201, "put", json=p)
        finally:
            del p
        if not isinstance(r, dict) or "id" not in r:
            raise ValueError(
                f'"{self._base}/session/{id}/regedit" returned an invalid result'
            )
        return int(r["id"])


class Filter(object):
    def __init__(self):
        self.pid = None
        self.session = None
        self.fallback = None
        self.evelated = None
        self.exclude = list()
        self.include = list()

    def json(self):
        r = dict()
        if isinstance(self.session, bool):
            r["session"] = self.session
        if isinstance(self.evelated, bool):
            r["elevated"] = self.evelated
        if isinstance(self.fallback, bool):
            r["fallback"] = self.fallback
        if isinstance(self.pid, int) and self.pid > 0:
            r["pid"] = self.pid
        if isinstance(self.exclude, list) and len(self.exclude) > 0:
            r["exclude"] = self.include
        if isinstance(self.include, list) and len(self.include) > 0:
            r["include"] = self.include
        return r

    def clear(self):
        self.pid = None
        self.session = None
        self.fallback = None
        self.evelated = None
        self.exclude = list()
        self.include = list()

    def __str__(self):
        b = list()
        if isinstance(self.pid, int) and self.pid > 0:
            b.append(f"PID:      {self.pid}")
        if isinstance(self.include, list) and len(self.include) > 0:
            b.append(f"Include:  {', '.join(self.include)}")
        if isinstance(self.exclude, list) and len(self.exclude) > 0:
            b.append(f"Exclude:  {', '.join(self.exclude)}")
        if isinstance(self.session, bool):
            b.append(f"Desktop:  {str(self.session)}")
        if isinstance(self.evelated, bool):
            b.append(f"Elevated: {str(self.evelated)}")
        if isinstance(self.fallback, bool):
            b.append(f"Fallback: {str(self.fallback)}")
        if len(b) == 0:
            return "<empty>"
        return "\n   ".join(b)


class _Events(Thread):
    def __init__(self, sock):
        Thread.__init__(self)
        self._sock = sock
        self.daemon = False
        self._handle = None
        self._running = Event()
        self._select = DefaultSelector()
        self.name = "Cirrus Events Thread"

    def run(self):
        try:
            self._sock.run_forever(
                ping_interval=None,
                skip_utf8_validation=True,
                dispatcher=self,
            )
        except Exception as err:
            print(f"[!] Socket error: {err}!")
        print("[-] Socket closed.")

    def close(self):
        self._running.set()
        try:
            self._select.modify(self._handle, EVENT_WRITE)
            self._select.close()
            self._sock.sock.close()
            # NOTE(dij): Causes a slow quit
            self._sock.close()
        except (ValueError, AttributeError):
            pass

    def read(self, s, f):
        self._handle = s
        try:
            self._select.register(s, EVENT_READ)
            while self._select.select(None):
                if self._running.is_set():
                    return
                f()
        finally:
            self._handle = None
            self._select.close()
            del self._select
            del self._handle


class CirrusError(ValueError):
    def __init__(self, val, sub=None):
        ValueError.__init__(self, val)
        if nes(sub):
            self.sub = sub[0].upper() + sub[1:]
        else:
            self.sub = None

    def __str__(self):
        if nes(self.sub):
            return self.sub
        return super(__class__, self).__str__()
