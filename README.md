<div align="center">
<a href="https://gitlab.com/cossas/sacti/-/tree/master"><img src="sacti-logo.jpg"/>


![https://cossas-project.org](https://img.shields.io/badge/website-cossas--project.org-orange)
<!-- ![Commits](https://gitlab.com/cossas/sacti/-/jobs/artifacts/master/raw/ci_badges/commits.svg?job=badge:commits) -->
![Pipeline status](https://gitlab.com/cossas/sacti/badges/master/pipeline.svg)
<!-- ![Version](https://gitlab.com/cossas/sacti/-/jobs/artifacts/master/raw/ci_badges/version.svg?job=badge:version) -->
![License: MPL2.0](https://img.shields.io/badge/license-MPL2.0-orange)
<!-- ![License: MPL2.0](https://gitlab.com/cossas/sacti/-/jobs/artifacts/master/raw/ci_badges/license.svg?job=badge:license) -->
<!-- ![Code-style](https://gitlab.com/cossas/sacti/-/jobs/artifacts/master/raw/ci_badges/codestyle.svg?job=badge:codestyle) -->
![Code-style](https://img.shields.io/badge/codestyle-black-black)
</div></a>

<hr style="border:2px solid gray"> </hr>
<div align="center">
Securely aggregate CTI sightings and report them on MISP
</div>
<hr style="border:2px solid gray"> </hr>

_All COSSAS projects are hosted on [GitLab](https://gitlab.com/cossas/sacti/) with a push mirror to GitHub. For issues/contributions check [CONTRIBUTING.md](CONTRIBUTING.md)_

## What is it?
The secure aggregator of cyber threat intelligence (SACTI) is an MPC functionality to securely aggregate CTI sightings and report this on MISP.
In the SACTI protocol, the aggregator (central party) requests all participants to report a number for each threat of the listed cyber threats. The participants respond by sending each other participant a Shamir secret shared list of sightings. In a joint computation, the parties check both the validity of the inputs and that the number of zero-sightings per thread does not exceed the threshold. If so, the responses are jointly reconstructed and published on MISP via the aggregator. The software is written in Python based on [TNO's MPC lab](https://www.tno.nl/mpclab).

More information can be found on [cossas-project.org](https://cossas-project.org/portfolio/sacti/).

## Installation
To install SACTI, you'll need a running MISP instance

### Setup MISP
First, install MISP in a Docker container

```console
git clone https://github.com/MISP/misp-docker
cd misp-docker
cp template.env .env
docker-compose up --build -d
```

when MISP is up press `Ctrl+C` in order to fix a config file

```console
sudo sed -i "s@'baseurl'[\t ]*=> 'localhost',@'baseurl' => 'http://127.0.0.1',@g" data/web/app/Config/config.php
docker-compose up
```

### Configure MISP

- [Login](http://127.0.0.1/users/login) with the default credentials:
  - Username: `admin@admin.test`
  - Password: `admin` (you'll be forced to set a new password)
- Click the **Auth Keys** button and then **Add authentication key**.
- Create and copy the new key.
- In the `config.py` file set `MISP_KEY=<your_fresh_key>`.

#### Add events from feeds

- Copy and paste the content of `feed_index.json` to [import feeds](http://127.0.0.1/feeds/importFeeds) and press **Add**.
- Enable all feeds.
- Click on **Fetch and store all feed data**.
- The [events list](http://127.0.0.1/events/index) will now populate (it might take a while to fetch everything).
- Alternatively, you can create dummy events in the event list.

### Install liboqs
SACTI depends on `liboqs` for its operations, so you need to install that.

- Build `liboqs` according to the [liboqs building instructions](https://github.com/open-quantum-safe/liboqs#linuxmacos) with shared library support enabled (add `-DBUILD_SHARED_LIBS=ON` to the cmake command), followed (optionally) by a `sudo ninja install` to ensure that the shared library is visible system-wide (by default it installs under `/usr/local/include` and `/usr/local/lib` on Linux/macOS).

- On Linux/macOS you may need to set the `LD_LIBRARY_PATH` (`DYLD_LIBRARY_PATH` on macOS) environment variable to point to the path to liboqs' library directory, e.g.

  ```console
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
  ```

Assuming `liboqs.so.*` were installed in `/usr/local/lib` (true if you ran `sudo ninja install` after building liboqs).

- On Windows ensure that the liboqs shared library `oqs.dll` is visibly system-wide. Use the **Edit the system environment variables** Control Panel tool or type in a Command Prompt.

  ```microsoftshell
  set PATH="%PATH%;C:\some\dir\liboqs\build\bin"
  ```

Replacing the paths with the ones corresponding to your system.

## Usage

- Set up the environment with `poetry install` or, alternatively, with `pip install -r requirements.txt`.
- Check the parameters in `config.py`.
- Run the PKI setup script `python sacti/pq_pki_utils.py`.
  If you want to simulate more than 3 subscribers, you'll need to create empty key files first in `PKI/Party_<number>`.
- For a 3-party example run (the sightings and damage value will be randomly generated for each party):
  - `python sacti/aggregator.py`
  - `python sacti/party.py 1 8011`
  - `python sacti/party.py 2 8012`
  - `python sacti/party.py 3 8013`

## Contributing

Contributions to SACTI are highly appreciated and more than welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for more information about our contributions process.

## About

The SACTI software was developed by [TNO](https://tno.nl) in the European [Prometheus](https://www.h2020prometheus.eu/) project, which received funding from the European Union's Horizon 2020 Research and Innovation program under Grant Agreement No. 780701.
