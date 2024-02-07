# Getting Started
### Env variables for Service account
After creating a service account in the prisma cloud console you wish to interact with, add it to your corrosponding (~/.zshrc / ~/.bashrc). Please see the example below

```
export PC_IDENTITY='****************************************'
export PC_SECRET='*******'
```

After reloading your shell by exiting and opening a new terminal window, your env variables can now be accessed from the python script.

### Requirements.txt
To install the required packages via pip, run `pip install -r requirements.txt`
This will install the needed packages to your system
### Usage `python main.py --url https://api0.prismacloud.io/cloud --type GET`
`python main.py --url https://app0.cloud.twistlock.com/panw-app0-310/api/v1/images --type GET --json true`
Please see the `docs/examples` file for more examples
