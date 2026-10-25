# Bus Filter Framework (BFF)

<p align="center">
  <img src="https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjA3T7ljwRoDbPJ3ld0ybkv1dw3qs9Dk8xZrVtxnzN1BuRb7LzIVEmpzrL62lFOCSQFdmrj31fxv7QezNP4YzGoSI0tckC8giHW0DrSn1WcuAsh1hJyA_05JBcYK5GUXeg/s113/imageedit_1_4876990325.png" />
</p>

<p align="center">
  <strong>Reusable infrastructure for building Windows KMDF Bus Filter Drivers.</strong>
</p>

Bus Filter Framework (BFF) is an open-source framework for developing Windows Kernel-Mode Driver Framework (KMDF) Bus Filter Drivers. It provides reusable infrastructure for filtering bus-enumerated child devices before their function drivers are loaded, while handling common low-level WDM and Plug and Play (PnP) operations required by this driver pattern.

BFF is intended to reduce repeated Bus Filter infrastructure work so driver developers can focus on behavior specific to their target bus and child devices.

## Why BFF?

- **KMDF-oriented development** — integrate Bus Filter functionality into a KMDF-based driver.
- **Reusable PnP infrastructure** — reduce repeated work around bus relations, child-device filtering, and lifecycle management.
- **Child-device filtering** — create filter device objects for bus-enumerated child devices before their function drivers are loaded.
- **No DMF dependency** — use BFF without adopting the broader DMF framework.
- **Working sample** — explore a sample KMDF Bus Filter Driver integrated with BFF.

## Is BFF a Fit?

BFF may be useful when you need to manage or filter child devices enumerated by a bus, customize selected PnP behavior, or reuse Bus Filter infrastructure across driver projects.

BFF is **not** a universal Windows device-filtering framework. If you only need to intercept requests for one known function device, a conventional function filter may be more appropriate. File-system filtering, file-content inspection, and complete data-loss-prevention solutions require additional or different enforcement mechanisms.

For a detailed explanation of the device-stack model, `BusRelations`, child-device lifecycle, `BFFDEVICE`, and the sample architecture, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Key Features

- KMDF-oriented Bus Filter infrastructure.
- Child-device filter creation and lifecycle management.
- Integration points for selected PnP operations and Bus Relations processing.
- Support for selected child-device identity customization, including Compatible IDs.
- Framework access to related device-stack objects and remove-lock management.
- Integration into a KMDF driver without requiring DMF.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the conceptual model and limitations. The precise supported behavior is defined by the public API and sample implementation.

## Quick Start

### Requirements

The current build environment targets:

- Windows 10 or later.
- Visual Studio 2022.
- Windows Driver Kit (WDK) 10.0.26100 or later.
- NuGet package restore.

The projects use the WDK NuGet packages introduced with WDK 26100.

### Clone the Repository

The sample depends on the `WDKStorPortVirtualMiniport` Git submodule. Clone recursively:

```powershell
git clone --recurse-submodules https://github.com/abysdom/bus-filter-framework.git
```

If you have already cloned the repository without its submodules:

```powershell
git submodule update --init --recursive
```

### Build

Open `mp\mp.sln` in Visual Studio and build the solution. You can also build from a Developer Command Prompt:

```powershell
msbuild mp\mp.sln
```

NuGet package restore must be available to the build environment. GitHub Actions builds the project to help detect build regressions.

## Sample Driver

The `BusFilter/` directory contains a sample KMDF Bus Filter Driver demonstrating BFF initialization, callbacks, child-device filter creation, PnP handling, device-interface registration, Compatible ID customization, interaction with the underlying bus driver, and KMDF device/queue management.

The sample is designed to work with `WDKStorPortVirtualMiniport`, included as a Git submodule. It demonstrates BFF integration with a virtual bus. See [ARCHITECTURE.md](ARCHITECTURE.md#sample-driver-architecture) for the component diagram and responsibilities.

## Installing the Sample Driver

The sample is intended for development and experimentation. Use a disposable test system or virtual machine, and ensure you have a recovery path before changing driver settings. The driver package requires an appropriate test-signing environment.

Enable test signing from an elevated command prompt:

```powershell
bcdedit /set testsigning on
```

Reboot Windows after enabling test signing. Create the sample root-enumerated device:

```powershell
devgen /add /bus ROOT /hardwareid root\mp
```

Then install the driver package:

```powershell
pnputil /add-driver install.inf /install
```

The `install.inf` package is generated by the `install` project. The `WDKStorPortVirtualMiniport` submodule also contains installation documentation for the virtual bus device.

## Uninstalling the Sample Driver

Remove the root-enumerated device:

```powershell
pnputil /remove-device /deviceid root\mp
```

Then remove the installed driver package:

```powershell
pnputil /delete-driver oemXX.inf
```

Replace `oemXX.inf` with the published OEM INF name assigned by Windows. For details about the underlying virtual miniport device, see the documentation in `WDKStorPortVirtualMiniport/`.

## Compatibility and Testing

The current project targets Windows kernel-mode driver development with KMDF, WDK 10.0.26100 or later, Visual Studio 2022, and the corresponding WDK NuGet packages.

The sample is primarily a development and learning resource. Before production use, verify supported Windows and KMDF versions, signing and deployment requirements, and behavior on the target hardware and bus topology.

More comprehensive Windows Hardware Lab Kit (HLK) testing documentation is planned and is not yet included in this repository. Until it is available, perform appropriate driver validation for your target hardware, Windows versions, and deployment scenario.

## Repository Layout

| Path | Description |
|---|---|
| `bff/` | BFF framework implementation and public header |
| `BusFilter/` | Sample Bus Filter Driver |
| `install/` | Driver package project |
| `LegalPropertyPage/` | GPL v3 notice property-page DLL used by the sample |
| `WDKStorPortVirtualMiniport/` | Git submodule containing the sample's underlying bus driver |
| `mp/` | Visual Studio solution |
| `.github/workflows/` | GitHub Actions workflows |
| `screenshots/` | Documentation screenshots |

## Documentation

- [Architecture](ARCHITECTURE.md) — device-stack model, Bus Relations, child-device lifecycle, object model, and sample architecture.
- [Public API](bff/bff.h) — declarations and API contracts.
- [Sample implementation](BusFilter/Driver.c) — example BFF integration.
- [Project documentation and FAQ](https://bus-filter-framework.blogspot.tw/).

## Commercial Licensing and Engineering Services

BFF Community Edition is licensed under GPL v3. A commercial license is available for organizations that need to incorporate BFF into proprietary software, distribute closed-source Windows drivers, obtain commercial technical support, or request customized development services.

For commercial licensing and engineering inquiries, contact the project maintainer through the project's published contact channel. See [LICENSE](LICENSE) for the Community Edition license text.

## Contributing

Contributions are welcome. Please submit pull requests through GitHub and review the following before contributing:

- [`CONTRIBUTING.md`](CONTRIBUTING.md)
- [`CONTRIBUTOR_LICENSE_AGREEMENT.md`](CONTRIBUTOR_LICENSE_AGREEMENT.md)
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

By submitting a contribution, you agree to the project's Contributor License Agreement (CLA). The CLA allows contributors to retain copyright ownership while granting the project maintainer the rights necessary to distribute the project under open-source and commercial licenses.

Please ensure that changes follow the existing coding style, are documented appropriately, build with the supported WDK, and include relevant testing information where applicable.

## License

Bus Filter Framework Community Edition is licensed under the GNU General Public License version 3 (GPL v3). See [LICENSE](LICENSE) for the complete license text.

## Community and Support

For questions, discussions, bug reports, and feature requests, use the project's GitHub repository. If BFF helps your project and you would like to support its continued development, see the [donations page](https://bus-filter-framework.blogspot.com/p/donation.html).

You can also explore the project using:

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/abysdom/bus-filter-framework)
