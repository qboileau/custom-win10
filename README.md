# custom-win10

From ChrisTitusTech [project](https://github.com/ChrisTitusTech/win10script) and [video](https://www.youtube.com/watch?v=PYOsevW3KdA)   
- Debloat Windows 10 by removing/desabling some services and apps  
- Configure some security and privacy settings  
- And install softs from `essential-packages.config` with `chocolatey`

## Install 
Download repository zip and extract 

Start powershell commandline in administrator and remove execution restriction
```powershell
 Set-ExecutionPolicy Unrestricted
```
Go to extracted directory
and run `customize.ps1` script

From here we can run post install to setup more packages or generate ISO from this minimal version of Windows 10

## Post install 
Install packages from `post-install-packages.config` run in powershell with administrator rights in extracted directory: 
```powershell
choco install .\post-install-packages.config -y
```


## Build custom ISO

### Preparation
1. Download latest Windows ISO using [tool](https://www.microsoft.com/en-au/software-download/windows10)
2. Download [WinToolKit  1.7.0.15 ](https://www.majorgeeks.com/files/details/win_toolkit.html) 
3. Extract ISO in a folder using 7zip
4. If `source\install.esd` exist in a powershell admin inside source folder
```powershell
# List Indexes (versions) in ESD file
> dism.exe /Get-WimInfo /wimfile:install.esd

Outil Gestion et maintenance des images de déploiement
Version : 10.0.19041.1

Détails pour l´image : install.esd

Index : 1
Nom : Windows 10 Famille
Description : Windows 10 Famille
Taille : ...

...

# Extract one index into an install.wim file
> dism.exe /export-image /sourceimagefile:install.esd /sourceindex:1 /destinationimagefile:install.wim /compress:max /checkintegrity 
```

### Customization
1. Open WinToolkit and All-In-One Integrator and select install.wim file
2. Select windows version to customize
3. Load and apply presets file `wintoolkit-aio-remove-settings.ini`
4. Configure additional tweaks 
5. Run Start that will remove packages/services and rebuild wim image
6. When finish close current window

### Create/Update Unattended file
1. In WinToolkit, run Unattended Creator in intermediat tab
2. Import `Autounattended.xml` file
3. Modify unattended configuration
4. Save file in extracted ISO folder

### Create ISO
1. First re-convert `install.wim` to `install.esd`
```powershell
# Remove old install.esd
> rm .\install.esd

# Convert index 1 install.wim to install.esd 
> dism.exe /export-image /sourceimagefile:install.wim /sourceindex:1 /destinationimagefile:install.esd /compress:max /checkintegrity

# Remove temporary install.wim
> rm .\install.wim
```
2. In WinToolkit Create ISO from folder 
