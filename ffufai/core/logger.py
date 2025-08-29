# Colored logging
def log(level, message):
    colors = {
        "info": "\033[94m", "success": "\033[92m",
        "warning": "\033[93m", "error": "\033[91m",
        "ai": "\033[95m", "step": "\033[96m",
    }
    reset = "\033[0m"
    prefix = {
        "info": "[*]", "success": "[+]",
        "warning": "[!]", "error": "[-]",
        "ai": "[AI]", "step": "[=]",
    }
    print(f"{colors.get(level,'')}{prefix.get(level,'[*]')} {message}{reset}")
