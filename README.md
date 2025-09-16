#--- new env ---
1. build a env in the code dir
   python3 -m venv env (note: evn*/ dir is not tracked in git)
   source env/bin/activate

2. install needed package - example
   pip install pandas openpyxl

3. if using vscode
   open the Command Palette 
   search Python: select interpreter
   choose the env-diff-ip/

4. deactivate env
   deactivate


#-- keyring (Mac and Win) --
1. setup kerying secret in command line - set password
   python3 -c 'import keyring; keyring.set_password("service_name", "user_name", "password")'
   python3 -c 'import keyring; svc='svc_name'; user="xxx"; pwd="xxx"; keyring.set_password(svc, 'username', user); keyring.set_password(svc, 'password', pwd)''

#--- diff_sh ---
for diff show outputs


#--- diff_cf ---
for diff running config
1. -f force, ignore hostname check