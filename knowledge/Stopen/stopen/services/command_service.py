"""命令服务（渗透场景放宽）"""
import subprocess, os, json
from app_config.settings import STORAGE_DIR

REQUEST_LOG_PATH = STORAGE_DIR / "command_requests.json"


class CommandService:
    def execute(self, cmd, workdir=".", timeout=30):
        """执行命令，渗透场景下允许更多操作"""
        try:
            if os.name == "nt":
                shell_cmd = ["powershell.exe", "-NoProfile", "-NonInteractive",
                             "-ExecutionPolicy", "RemoteSigned", "-Command", cmd]
            else:
                shell_cmd = ["/bin/sh", "-c", cmd]
            result = subprocess.run(
                shell_cmd, capture_output=True, text=True,
                timeout=timeout, cwd=str(workdir) if workdir else None,
                encoding="utf-8", errors="replace",
            )
            self._log(cmd, result.returncode == 0)
            return {"success": result.returncode == 0,
                    "output": (result.stdout or "")[-5000:],
                    "error": (result.stderr or "")[-2000:]}
        except subprocess.TimeoutExpired:
            return {"success": False, "output": "", "error": f"超时({timeout}s)"}
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}

    def _log(self, cmd, success):
        import datetime as dt
        data = json.loads(REQUEST_LOG_PATH.read_text(encoding="utf-8") if REQUEST_LOG_PATH.exists() else "[]")
        data.append({"timestamp": dt.datetime.now().isoformat(), "command": cmd, "success": success})
        if len(data) > 100:
            data = data[-100:]
        REQUEST_LOG_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


command_service = CommandService()
