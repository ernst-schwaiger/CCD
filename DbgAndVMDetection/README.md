# Build and Install Demo

- If not yet installed, install VS Code for Windows
- Install VS Build Tools (Variant "Desktop Development with C++"): https://download.visualstudio.microsoft.com/download/pr/e28bf043-c63e-47d0-b6e9-c418229fb008/999a275192383f1da35ccf655568645534b632770c556f64f866f3d3f7b53b32/vs_BuildTools.exe
- Start a Windows command prompt "cmd.exe"
- Run "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" (assuming VS 2022). This will set up the environment for building the demo
- cd into the `DbgAndVMDetection` directory
- run `code .`
- In VSCode, press "F5" for running the application in a debugger", which will also compile it before