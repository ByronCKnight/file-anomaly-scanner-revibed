# Third-Party Software Notices and Attributions

This project, **File Anomaly & Virus Threat Scanner**, incorporates, connects with, or depends upon third-party open-source software, runtime redistributables, test specifications, and cybersecurity intelligence APIs. This document details the respective copyright notices, open-source licenses, trademark acknowledgments, and terms of service compliance requirements.

---

## Table of Contents

1. [Microsoft .NET 8, WPF, and ASP.NET Core](#1-microsoft-net-8-wpf-and-aspnet-core)
2. [Microsoft Edge WebView2 Runtime](#2-microsoft-edge-webview2-runtime)
3. [React 18 & Vite](#3-react-18--vite)
4. [VirusTotal v3 Public REST API](#4-virustotal-v3-public-rest-api)
5. [MITRE ATT&CK® Framework](#5-mitre-attck-framework)
6. [EICAR Standard Anti-Virus Test File](#6-eicar-standard-anti-virus-test-file)
7. [PowerShell SDK (System.Management.Automation)](#7-powershell-sdk-systemmanagementautomation)

---

## 1. Microsoft .NET 8, WPF, and ASP.NET Core

* **Project**: .NET Core, ASP.NET Core, Windows Presentation Foundation (WPF)
* **Copyright**: © .NET Foundation and Contributors
* **License**: MIT License
* **Repository**: [https://github.com/dotnet/runtime](https://github.com/dotnet/runtime), [https://github.com/dotnet/aspnetcore](https://github.com/dotnet/aspnetcore), [https://github.com/dotnet/wpf](https://github.com/dotnet/wpf)

```
The MIT License (MIT)

Copyright (c) .NET Foundation and Contributors

All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 2. Microsoft Edge WebView2 Runtime

* **Project**: Microsoft Edge WebView2 Control & Evergreen Runtime
* **Copyright**: © Microsoft Corporation
* **Package**: `Microsoft.Web.WebView2` (NuGet)
* **License**: Microsoft Software License Terms / Microsoft WebView2 Runtime Redistributable License
* **Website**: [https://developer.microsoft.com/en-us/microsoft-edge/webview2/](https://developer.microsoft.com/en-us/microsoft-edge/webview2/)

The Microsoft Edge WebView2 component embedded within this desktop application enables modern web UI hosting via the native Chromium-powered Microsoft Edge rendering engine. Redistribution and runtime deployment comply with the Microsoft Software License Terms for Microsoft Edge WebView2 and the NuGet package license terms.

---

## 3. React 18 & Vite

### React 18
* **Project**: React (`react`, `react-dom`)
* **Copyright**: © Meta Platforms, Inc. and affiliates
* **License**: MIT License
* **Repository**: [https://github.com/facebook/react](https://github.com/facebook/react)

```
MIT License

Copyright (c) Meta Platforms, Inc. and affiliates.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Vite & @vitejs/plugin-react
* **Project**: Vite
* **Copyright**: © 2019-present Evan You & Vite Contributors
* **License**: MIT License
* **Repository**: [https://github.com/vitejs/vite](https://github.com/vitejs/vite)

```
MIT License

Copyright (c) 2019-present, Yuxi (Evan) You and Vite contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 4. VirusTotal v3 Public REST API

* **Service**: VirusTotal v3 Public API
* **Provider**: Chronicle Security / Google Cloud / Google LLC
* **Terms of Service**: [https://www.virustotal.com/gui/terms-of-service](https://www.virustotal.com/gui/terms-of-service)
* **Privacy Policy**: [https://www.virustotal.com/gui/privacy-policy](https://www.virustotal.com/gui/privacy-policy)

### Terms of Service Compliance & Non-Commercial Attribution Notice:
1. **Attribution**: Multi-engine antivirus threat intelligence, cryptographic file lookup telemetry, and cloud sandbox behavioral analytics are powered by the **VirusTotal v3 REST API**.
2. **Independence**: This software application is an independent, community-developed defensive security project and is **not affiliated with, officially endorsed by, or sponsored by VirusTotal, Chronicle Security, or Google LLC**.
3. **Non-Commercial Tier Compliance**: Use of the VirusTotal Public API tier within this project is strictly intended for individual, educational, and non-commercial defensive research purposes under VirusTotal's public rate-limiting policy (4 requests per minute, 500 requests per day). Organizations utilizing this tool for enterprise operations or commercial workflows are responsible for acquiring a commercial VirusTotal Premium API subscription.
4. **Data Handling & Sample Privacy**: Lookups conducted by default query cryptographic SHA-256 hashes only. When using the interactive cloud binary upload workflow, users acknowledge that submitted binary payloads are distributed to dozens of participating antivirus companies and security researchers worldwide in accordance with VirusTotal's terms.

---

## 5. MITRE ATT&CK® Framework

* **Organization**: The MITRE Corporation
* **Framework**: MITRE ATT&CK® (Adversarial Tactics, Techniques, and Common Knowledge)
* **Terms of Use**: [https://attack.mitre.org/resources/terms-of-use/](https://attack.mitre.org/resources/terms-of-use/)

### Trademark & Attribution Notice:
> **© The MITRE Corporation. MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.**

Behavioral anomaly categorization, cloud sandbox telemetry tagging, and threat detection classifications within this application reference MITRE ATT&CK® tactics, techniques, and sub-techniques (e.g., T1059.001 Command and Scripting Interpreter: PowerShell, T1027 Obfuscated/Compressed Files and Information, T1036 Masquerading). This reference is made under fair use and MITRE ATT&CK terms of use for educational and defensive cybersecurity analysis.

---

## 6. EICAR Standard Anti-Virus Test File

* **Specification**: Standard Anti-Virus Test File
* **Developing Entities**: European Institute for Computer Antivirus Research (EICAR) and Computer Antivirus Research Organization (CARO)
* **Website**: [https://www.eicar.org/?page_id=3950](https://www.eicar.org/?page_id=3950)

### Inert Test Specification Notice:
The synthetic test suite and demonstration fixtures included with this project utilize the standardized EICAR test string (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`). 

This character pattern is **completely inert, non-viral, and harmless**. It is designed solely as an industry-standard mechanism to safely verify the end-to-end functionality, parsing pipelines, and alert mechanisms of antivirus and heuristic scanning software without exposing computing assets to live, malicious software.

---

## 7. PowerShell SDK (System.Management.Automation)

* **Project**: PowerShell Core / Management Automation SDK
* **Copyright**: © Microsoft Corporation
* **Package**: `System.Management.Automation` (Version 7.4.5)
* **License**: MIT License
* **Repository**: [https://github.com/PowerShell/PowerShell](https://github.com/PowerShell/PowerShell)

Used by the backend `PowerShellAstScanner` engine to parse PowerShell scripts into structured Abstract Syntax Trees (AST) for deep detection of obfuscated execution cradles, dynamic invocations (`Invoke-Expression`, `IEX`), and unescaped command payloads.
