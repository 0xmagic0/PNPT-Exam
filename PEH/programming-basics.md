# Setup a reproducible environment
1. Git
2. Virtual environment
```bash
python3 -m venv venv-name
source venv-name/bin/activate
pip install package-name
```
3. Recording project dependencies
```bash
pip freeze > requirements.txt
# other users can use this requirements.txt
pip install -r requirements.txt
```
4. Sharing environment files with git
    - Create a .gitignore file and add the `venv-name` folder since this is not important.
    - Add other files to be ignored.
5. More advanced: use docker
