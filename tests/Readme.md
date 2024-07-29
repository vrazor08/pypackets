# Tests

For running tests you need to compile go sniffer in `tests/sniff/`
```
go build
```
and the you can run tests using
```
su  # it's recommended because for running tests you need CAP_NET_RAW capability(sudo or su)
# activate your env
python -m pytest tests/
```
or
```
sudo path_to_python_in_env -m pytest tests/
```