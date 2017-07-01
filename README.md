# DISCLAIMER:  This isn't a great peice of software.  Inspect the code and use at your own risk.

So you want to change your Let's Encrypt account's key?  Here's a quick-start guide:
- install this app (binaries are commited in this repo)
- copy your current PEM encoded account key to `old.key` in your current-working-directory
- copy your desired account key to `new.key` in your current-working-directory
- run the app and pass it your Let's Encrypt account number as an argument

On linux, this might look like:
```bash
wget 'https://github.com/kf6nux/letsencrypt-account-key-change/blob/master/leakc_linux_amd64?raw=true'
chmod +x leakc_linux_amd64
cp /path/to/your/current_account.key ./old.key
cp /path/to/your/desired_account.key ./new.key
./leakc_linux_amd64 $youraccountnumber
# inspect output
```

# CONTRIBUTING

This tool isn't worth spending a lot of time on.  Changes will only be merged if LE breaks its API or there's a major flaw in this implementation.  Please feel free to fork this if you need greater functionality.
