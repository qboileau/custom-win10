
# custom-win10
From https://github.com/ChrisTitusTech/win10script project.  
- Debloat Windows 10 by removing/desabling some services and apps  
- Configure some security and privacy settings  
- And install softs from `essential-packages.config` with `chocolatey`

# Install 
Download repository zip and extract 

Start powershell commandline in administrator and remove execution restriction
```powershell
 Set-ExecutionPolicy Unrestricted
```
Go to extracted directory
and run `customize.ps1` script

From here we can run post install to setup more packages or generate ISO from this minimal version of Windows 10

# Post install 
Install packages from `post-install-packages.config` run in powershell with administrator rights in extracted directory: 
```powershell
choco install .\post-install-packages.config -y
```
