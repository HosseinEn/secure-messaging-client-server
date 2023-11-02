
def pp(text, color):
	if color == "DG":
		return f"\033[1;30;40m{text}\033[0m"
	elif color == "B":
		return f"\033[0;37;41m{text}\033[0m"
	elif color == "BG":
		return f"\033[1;31;40m{text}\033[0m"
	elif color == "BM":
		return f"\033[0;37;46m{text}\033[0m"
	elif color == "C":
		return f"\033[1;32;40m{text}\033[0m"
	elif color == "M":
		return f"\033[1;33;40m{text}\033[0m"
	