# MidPoint Password Agent for Active Directory

Captures Active Directory password changes on Domain Controllers and forwards them to a configurable MidPoint REST endpoint in real time.

The solution runs on every Domain Controller and consists of two decoupled components:

| Component | Language | Role | Docs |
|---|---|---|---|
| **Listener** | C++ | LSA Password Notification Filter. Captures the cleartext password at change time and writes it to a local filesystem queue. | [`docs/development/listener/README.md`](docs/development/listener/README.md) |
| **Sender** | C# | Windows service that reads the queue and forwards events to the target REST API. | [`docs/development/sender/README.md`](docs/development/sender/README.md) |

---

## Documentation

| Section | Description |
|---|---|
| [Development](docs/development/README.md) | Setting up a dev environment, building, and testing the Listener & Sender components |
| [Administration](docs/administration/readme.md) | Installing, configuring, and operating the agent |
| [Listener](docs/development/listener/README.md) | C++ LSA Password Notification Filter module docs |
| [Sender](docs/development/sender/README.md) | C# Windows service module docs |

---

## Repository layout

```
.
├── docs/                    # Documentation
├── installation/            # Listener + Sender instalation scripts
├── listener/                # C++ LSA filter DLL
│   ├── CMakeLists.txt
│   ├── PasswordFilter.def   # Linker exports
│   └── src/                 # Listener source files
│   └── tests/               # Listener tests
├── MockServer/              # C# Mocked Server application (used for testing)
├── sample-installation/     # Midpoint example installation
├── scripts/                 # Powershell scripts uploaded during installation
├── sender/                  # C# Windows service app
│   ├── Program.cs           # Application builder
│   ├── sender.csproj        # C# app definition
├── sender.DPAPI/            # C# app used for midpoint password update
├── sender.Tests/            # C# Sender service app Tests
└── justfile                 # Just recipes
└── Installer.wixproj        # Wix project definition
└── Package.wxs              # Wix installation steps
└── README.md
```
