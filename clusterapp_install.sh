#!/bin/bash
# ClusterApp: setup and configuration

######## VARIABLES #########
# Any global environment variables should be defined in this section
export PIP_ROOT_USER_ACTION=ignore
export PIP_DISABLE_PIP_VERSION_CHECK=1
RESET='\e[0m'
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'

OS=""
OS_VERSION=""
PKG_MANAGER=""

DB_NAME_PG_HBA="all"
AUTH_METHOD="scram-sha-256"
LISTEN_ADDRESSES="*"

APP_DB_NAME="clusterapp"
ONLINE_CONNECTION=true
SUPPORTED_UBUNTU_VERSIONS=("18.04" "20.04" "22.04")
SUPPORTED_CENTOS_VERSIONS=("7" "8" "9" "10")
# DISK_SPACE in GB
DISK_SPACE=30
DB_PORT=5432
BACK_PORT=8000
FRONT_PORT=3000
PG_VERSION=15
MARIADB_VERSION=11.4
PG_VERSIONS_LIST=(10 11 12 13 14 15 16)
PYTHON_VERSION="3.10.13"
CURRENT_PATH=$(pwd)
backend_path="${CURRENT_PATH%/}/backend"
tasks_path="${CURRENT_PATH%/}/tasks"
RPM_PATH="$tasks_path/rpms"
LOGFILE="${CURRENT_PATH%/}/clusterapp_setup.log"

# Redirect stdout and stderr to the log file and terminal
exec > >(tee -a "$LOGFILE") 2>&1

echo -e "${BLUE}::: Welcome to the ClusterApp Application Installation :::${RESET}"
echo -e "${BLUE}::: -------------------------------------------------- :::${RESET}"
######## FIRST CHECK ########
# Check RAM, CPU, and Disk Space Requirements
echo "::: Checking system requirements..."

# Get the hostname from /etc/hostname
if [ -f /etc/hostname ]; then
    hostname=$(cat /etc/hostname | xargs)
else
    echo -e "${RED}ERROR: /etc/hostname file not found. Exiting...${RESET}"
    exit 1
fi

# Get the IP address using ifconfig
# ip_address=$(ifconfig | awk '/inet / {print $2}' | grep -v '127.0.0.1' | xargs)
ip_address=$(ip addr show | awk '/inet / {print $2}' | grep -v '127.0.0.1' | cut -d/ -f1)

iam=$(whoami | xargs)
if [ "$iam" != "root" ]; then
    echo -e "${RED}ERROR: This script must be run as the root user to perform privileged operations.${RESET}"
    echo -e "${BLUE}::: Please login as the root user and rerun the script. Exiting...${RESET}"
    exit 1
fi

# Check RAM (Minimum 4GB)
total_ram_mb=$(free -m | awk '/^Mem:/{print $2}' | xargs)
total_ram_gb=$(awk "BEGIN { printf \"%.2f\", $total_ram_mb / 1024 }")
if [ $total_ram_mb -lt 3000 ]; then
    echo -e "${RED}ERROR: Insufficient RAM ${total_ram_gb}GB. Minimum 4GB of RAM is required. Exiting...${RESET}"
    exit 1
fi

# Check CPU (Minimum 2 CPUs)
cpu_count=$(nproc --all | xargs)
if [ $cpu_count -lt 2 ]; then
    echo -e "${RED}ERROR: Insufficient CPU $cpu_count cores. Minimum 2 CPUs are required. Exiting...${RESET}"
    exit 1
fi

echo -e "${GREEN}::: System requirements are met. Continuing with the installation...${RESET}"

####### FUNCTIONS ##########
# Note: The name 'function' refers to being within another function; otherwise, it is called directly.
# Function to check if a command is available
function command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Usage: spinner <pid>
function spinner() {
    local pid=$1
    local delay=0.50
    local spinstr='/-\|'
    while [ "$(ps a | awk '{print $1}' | grep "${pid}")" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "${spinstr}"
        local spinstr=${temp}${spinstr%"$temp"}
        sleep ${delay}
        printf "\b\b\b\b\b\b"
    done
    # Erase the spinner by overwriting with spaces
    printf "\b\b\b\b\b\b       \b\b\b\b\b\b"
    echo
}

# Usage: progress_bar <duration> <width>
function progress_bar() {
    local duration=${1}
    local width=${2}
    local elapsed
    local done
    local remain

    already_done() { for ((done=0; done<$elapsed*$width/$duration; done++)); do printf "="; done }
    remaining() { for ((remain=$elapsed*$width/$duration; remain<$width; remain++)); do printf " "; done }

    for (( elapsed=1; elapsed<=$duration; elapsed++ )); do
        printf "["
        already_done
        printf ">"
        remaining
        printf "] %s%%" $(( (elapsed*100)/duration ))
        sleep 1
        printf "\r"
    done
    printf "\n"
}

# Usage: display_progress <pid> <choice> (<msg> <duration>)
function display_progress() {
    local pid=$1
    local choice=$2
    local msg=${3:-""}
    local duration=${4:-10}
    local active_venv=${5:-false}
    local progress_bar_width=40

    case $choice in
        "spinner")
            spinner "$pid"
            ;;
        "progress_bar")
            progress_bar "$duration" "$progress_bar_width"  # Adjust duration and width as needed
            ;;
        *)
            echo "Invalid choice: $choice. Processing..."
            ;;
    esac
    wait $pid
    exit_status=$?

    if [ $exit_status -ne 0 ]; then
        echo -e "$msg"
        if [ "$active_venv" = "true" ]; then
            deactivate
        fi
        exit 1
    fi
}

# Verify there is enough disk space for the install
verifyFreeDiskSpace() {
    # Will check for 30GB free
    echo "::: Verifying free disk space..."
    local required_free_gigabytes="$DISK_SPACE"
    local existing_free_kilobytes=$(df -Pk "$CURRENT_PATH" | awk 'NR==2 {print $4}')
    local existing_free_gigabytes=$((existing_free_kilobytes / 1024 / 1024))

    # - Unknown free disk space, not an integer
    if ! [[ "${existing_free_kilobytes}" =~ ^([0-9])+$ ]]; then
        echo "WARNING: Unknown free disk space!"
        echo "::: Unable to determine available free disk space on this system."
        echo "::: You may continue with the installation; however, it is not recommended."
        read -r -p "::: If you are sure you want to continue, type YES and press enter: " response
        case $response in
            [Yy][Ee][Ss])
                ;;
            *)
                echo "::: Confirmation not received. Exiting..."
                exit 1
                ;;
        esac
    # - Insufficient free disk space
    elif [[ ${existing_free_gigabytes} -lt ${required_free_gigabytes} ]]; then
        echo "WARNING: Insufficient Disk Space!"
        echo "::: Your system appears to be low on disk space. $APP_DB_NAME recommends a minimum of ${required_free_gigabytes}GB."
        echo "::: You only have ${existing_free_gigabytes}GB free."

        echo -e "${RED}ERROR: Insufficient free space. Exiting...${RESET}"
        exit 1
    fi
    echo -e "${GREEN}::: Free disk space is sufficient.${RESET}"
}

distributionDetector() {
    echo "::: Checking the detected operating system and version..."
    silent_output="-yqq"
    # Checking OS distributor and version
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        if [ -n "$(grep -E '^ID=(ubuntu|debian)' /etc/os-release)" ]; then
            OS="ubuntu"
            PKG_MANAGER="apt-get"
            if grep -qi -E 'Ubuntu' /etc/os-release; then
                detected_os="Ubuntu"
            elif grep -qi -E 'Debian' /etc/os-release; then
                detected_os="Debian"
            fi

            if command_exists "lsb_release"; then
                OS_VERSION=$(lsb_release -r -s)
                # Check if the version is in the list of supported versions
                if ! [[ " ${SUPPORTED_UBUNTU_VERSIONS[@]} " =~ " ${OS_VERSION} " ]]; then
                    echo -e "${RED}::: Unsupported $detected_os version detected: $OS_VERSION.${RESET}"
                    echo -e "${RED}::: This script supports Ubuntu 18.04, 20.04 and 22.04 only. Exiting...${RESET}"
                    exit 1
                fi
            else
                echo -e "${RED}ERROR: lsb_release command not found. Unable to determine $detected_os version.${RESET}"
                exit 1
            fi

            major_version=$(echo "$OS_VERSION" | cut -d'.' -f1)
            # PG_DATA="/var/lib/postgresql/$PG_VERSION/main"
            pg_conf_path_ubuntu="/etc/postgresql/$PG_VERSION/$APP_DB_NAME/"
        elif [ -n "$(grep -E '^(ID="centos"|ID="rhel"|ID="fedora"|ID="rocky")' /etc/os-release)" ]; then
            OS="centos"
            # This is CentOS, Red Hat, Fedora or Rocky
            OS_VERSION="$(grep -E '^(VERSION_ID=|VERSION_ID "|VERSION_ID=.)' /etc/os-release | cut -d'"' -f2)"
            major_version="${OS_VERSION%%.*}"  # Extract the major version number

            if grep -qi -E 'CentOS' /etc/os-release; then
                detected_os="CentOS"
            elif grep -qi -E 'Fedora' /etc/os-release; then
                detected_os="Fedora"
            elif grep -qi -E 'RHEL' /etc/os-release; then
                detected_os="Red Hat"
            elif grep -qi -E 'Rocky' /etc/os-release; then
                detected_os="Rocky"
            fi

            if [[ " ${SUPPORTED_CENTOS_VERSIONS[*]} " == *" $major_version "* ]]; then
                # OS_VERSION="$major_version"
                echo "::: Detected $detected_os version: $OS_VERSION"
            else
                echo -e "${RED}::: Unsupported $detected_os version detected: $major_version.${RESET}"
                echo -e "${RED}::: This script supports CentOS 7, 8 ,9 and 10 only. Exiting...${RESET}"
                exit 1
            fi

            if command_exists "dnf"; then
                PKG_MANAGER="dnf"
            elif command_exists "yum";then
                PKG_MANAGER="yum"
                silent_output="-y -q"
            fi

            # PG_DATA="/var/lib/pgsql/$PG_VERSION/data"
        else
            echo "::: Supported Operating Systems: Ubuntu 18, 20 and 22, CentOS 7 ,8 ,9 and 10."
            echo -e "${RED}::: Unsupported distribution was detected. Exiting...${RESET}"
            exit 1
        fi
    else
        echo -e "${RED}ERROR: /etc/os-release file not found. Unable to determine the operating system. Exiting...${RESET}"
        exit 1
    fi

    # Check if a package manager was found
    if [ -z "$PKG_MANAGER" ]; then
        echo -e "${RED}::: Unsupported distribution. Exiting...${RESET}"
        exit 1
    else
        echo -e "${BLUE}::: Operting system: $detected_os $OS_VERSION.${RESET}"
        echo -e "${BLUE}::: Using package manager: $PKG_MANAGER.${RESET}"
    fi

    if [ "$OS" = "ubuntu" ]; then
        locale-gen en_US.UTF-8 2>&1 >/dev/null
        update-locale LANGUAGE=en_US.UTF-8 2>&1 >/dev/null
        update-locale LC_ALL=en_US.UTF-8 2>&1 >/dev/null
        update-locale LANG=en_US.UTF-8 2>&1 >/dev/null
        update-locale LC_CTYPE=en_US.UTF-8 2>&1 >/dev/null
    fi
}

function ask_installation_type() {
    while true; do
        read -p "Do you want an online installation? (y/n): " choice
        case $choice in
            [Yy]*)
                ONLINE_CONNECTION=true
                echo "::: Online installation selected."
                break
                ;;
            [Nn]*)
                ONLINE_CONNECTION=false
                echo "::: Offline installation selected."
                break
                ;;
            *)
                echo "Please enter 'y' or 'n' only."
                ;;
        esac
    done
}

# Function to check if the machine has an online connection
check_online_connection() {
    echo "::: Checking for an online connection..."
    if ping -q -c 1 -W 1 8.8.8.8 >/dev/null; then
        echo -e "${BLUE}::: Machine has an online connection.${RESET}"
        ask_installation_type
    else
        ONLINE_CONNECTION=false
        echo -e "${BLUE}::: Machine does not have an online connection.${RESET}"
    fi
}

function confirm_and_update_packages() {
    echo "::: This script will update packages using $PKG_MANAGER."
    echo "::: WARNING: Please note that updating packages may affect system stability."

    while true; do
        read -p "Do you want to proceed with the update (Optional)? (y/n): " choice
        case $choice in
            [Yy]*)
                $PKG_MANAGER update $silent_output 2>&1 >/dev/null
                if [ $? -ne 0 ]; then
                    echo -e "${RED}ERROR: Failed to update packages.${RESET}"
                fi
                break
                ;;
            [Nn]*)
                echo "::: No updates were performed."
                break
                ;;
            *)
                echo "Please enter 'y' or 'n' only."
                ;;
        esac
    done
}

install_required_packages() {
    # Install required packages based on the package manager
    if ! command_exists "unzip"; then
        echo "::: Installing unzip package..."
        # $PKG_MANAGER install $silent_output "$RPM_PATH/$OS$major_version"/base/unzip* 2>&1 >/dev/null
        $PKG_MANAGER install $silent_output -y zip unzip
        if [ $? -ne 0 ]; then
            echo -e "${RED}ERROR: Failed to install unzip from $RPM_PATH/$OS$major_version/base/ directory. Exiting...${RESET}"
            exit 1
        fi
        echo -e "${GREEN}::: unzip has been installed.${RESET}"
    fi
    ### ????
    local file_to_check="rpms.zip"
    if [ -e "$tasks_path/$file_to_check" ]; then
        unzip "$tasks_path/rpms.zip" -d "$tasks_path/" 2>&1 >/dev/null &
        display_progress "$!" "spinner" "${RED}ERROR: Failed to unzip $tasks_path/$file_to_check. Exiting...${RESET}"

        rm -f "$tasks_path/$file_to_check"
    fi

    local packages=("sysstat" "net-tools" "tar" "rsync" "ca-certificates" "libjpeg-turbo-devel" "zlib-devel")
    if [ "$OS" = "centos" ]; then
        packages+=("which")
    fi
    local total_packages=${#packages[@]}
    local duration=${total_packages}  # Duration for the progress bar

    echo "::: Installing packages: ${packages[*]}"

    if [ "$ONLINE_CONNECTION" = true ]; then
        # Run the installation command for all packages together and display progress
        if [ "$OS" = "centos" ]; then
            # on some distributions - appstream repo may not be enabled by default
                $PKG_MANAGER --enablerepo=appstream install $silent_output "${packages[@]}" 2>&1 >/dev/null &
        else
                $PKG_MANAGER install $silent_output "${packages[@]}" 2>&1 >/dev/null &
        fi
    else
        if [ "$OS" = "centos" ]; then
            rpm_list=("which*.rpm" "sysstat*.rpm" "net-tools*.rpm" "rsync*.rpm" "tar*.rpm" "ca-certificates*.rpm")
            total_packages=${#rpm_list[@]}
            duration=${total_packages}
            (for rpm in "${rpm_list[@]}"; do
                $PKG_MANAGER localinstall $silent_output --nobest --disablerepo=* "$RPM_PATH/$OS$major_version/base"/$rpm 2>&1 >/dev/null
            done) &
        elif [ "$OS" = "ubuntu" ]; then
            deb_list=("sysstat*.deb" "net-tools*.deb" "rsync*.deb" "tar*.deb" "ca-certificates*.deb")
            total_packages=${#deb_list[@]}
            duration=${total_packages}
            (for deb in "${deb_list[@]}"; do
                $PKG_MANAGER install $silent_output "$RPM_PATH/$OS$major_version/base"/$deb 2>&1 >/dev/null
            done) &
        fi
    fi
    # Store the process ID of the background process
    bg_process_pid=$!
    display_progress "$bg_process_pid" "progress_bar" "${RED}ERROR: Some packages failed to install. Exiting...${RESET}" "$duration"

    echo -e "${GREEN}::: Packages: ${packages[*]} have been installed.${RESET}"

    if [ "$ONLINE_CONNECTION" = true ]; then
        # Need to install just for online case
        if [ "$OS" = "centos" ]; then
            echo "::: Installing epel-release..."
            confirm_and_update_packages

            $PKG_MANAGER install $silent_output epel-release 2>&1 >/dev/null &
            display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install epel-release package. Exiting...${RESET}" "1"

            echo -e "${GREEN}::: epel-release package has been installed.${RESET}"
        fi
    fi
}

# Define a function to check if a port is in use
check_port_in_use() {
    local port_to_check="$1"

    # Check if the port is in use
    if netstat -tuln | awk '{print $4}' | grep -q ":$port_to_check "; then
        echo -e "${RED}ERROR: Port $port_to_check is already in use.${RESET}"
        echo -e "${RED}Please ensure that the specified port is not currently in use. Exiting...${RESET}"
        exit 1
    else
        echo -e "${GREEN}::: Port $port_to_check is not in use. Proceeding...${RESET}"
    fi
}

function install_openssl() {
    local packages=()
    local total_packages=0
    local duration=${total_packages}  # Duration for the progress bar
    echo "::: Installing OpenSSL..."
    if [ "$OS" = "centos" ]; then
        if [ "$major_version" = "7" ]; then
            if [ "$ONLINE_CONNECTION" = true ]; then
                packages=("wget" "make" "gcc" "zlib-devel" "perl")
                total_packages=${#packages[@]}
                duration=${total_packages}  # Duration for the progress bar
                $PKG_MANAGER install $silent_output "${packages[@]}" 2>&1 >/dev/null &
                display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for OpenSSL. Exiting...${RESET}" "$duration"
                $PKG_MANAGER groupinstall $silent_output "Development tools" 2>&1 >/dev/null &
                display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for OpenSSL. Exiting...${RESET}" "$duration"
            else
                rpm_list=("make*.rpm" "gcc*.rpm" "zlib-devel*.rpm")
                total_packages=${#rpm_list[@]}
                duration=${total_packages}  # Duration for the progress bar
                (for rpm in "${rpm_list[@]}"; do
                    $PKG_MANAGER localinstall $silent_output --nobest --disablerepo=* "$RPM_PATH/$OS$major_version/base/openssl"/$rpm 2>&1 >/dev/null
                done) &
                display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for OpenSSL. Exiting...${RESET}" "$duration"

                rpm_count=$(find "$RPM_PATH/$OS$major_version/postgres/common" -type f -name '*perl*.rpm' | wc -l)
                duration=$((rpm_count + 1))
                $PKG_MANAGER localinstall $silent_output --nobest --disablerepo=* "$RPM_PATH/$OS$major_version/postgres/common"/perl*.rpm 2>&1 >/dev/null &
                display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install perl package for OpenSSL. Exiting...${RESET}" "$duration"

                rpm_count=$(ls -1 "$RPM_PATH/$OS$major_version/base/openssl"/*.rpm 2>/dev/null | wc -l)
                if [ "$rpm_count" -gt 0 ]; then
                    duration=$rpm_count
                    $PKG_MANAGER localinstall $silent_output --nobest --disablerepo=* "$RPM_PATH/$OS$major_version/base/openssl"/*.rpm 2>&1 >/dev/null &
                    display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for OpenSSL. Exiting...${RESET}" "$duration"
                else
                    echo -e "${RED}ERROR: No RPM files found in $RPM_PATH/$OS$major_version/base/openssl directory. Exiting...${RESET}"
                    exit 1
                fi
            fi
        # TO check
        elif [ "$major_version" = "8" ]; then
            if [ "$ONLINE_CONNECTION" = true ]; then
                $PKG_MANAGER install $silent_output perl 2>&1 >/dev/null &
                display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for OpenSSL. Exiting...${RESET}" "1"
            else
                rpm_count=$(ls -1 "$RPM_PATH/$OS$major_version/base/openssl"/*.rpm 2>/dev/null | wc -l)
                if [ "$rpm_count" -gt 0 ]; then
                    duration=$rpm_count
                    $PKG_MANAGER localinstall $silent_output --nobest --disablerepo=* "$RPM_PATH/$OS$major_version/base/openssl"/*.rpm 2>&1 >/dev/null &
                    display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for OpenSSL. Exiting...${RESET}" "$duration"
                else
                    echo -e "${RED}ERROR: No RPM files found in $RPM_PATH/$OS$major_version/base/openssl directory. Exiting...${RESET}"
                    exit 1
                fi
            fi
        fi
    elif [ "$OS" = "ubuntu" ]; then  ### Using file
        if [ "$major_version" = "20" ]; then
            deb_count=$(ls -1 "$RPM_PATH/$OS$major_version/base/openssl"/*.deb 2>/dev/null | wc -l)
            if [ "$deb_count" -gt 0 ]; then
                duration=$deb_count
                $PKG_MANAGER install $silent_output "$RPM_PATH/$OS$major_version/base/openssl"/*.deb 2>&1 >/dev/null &
                display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for OpenSSL. Exiting...${RESET}" "$duration"
            else
                echo -e "${RED}ERROR: No DEB files found in $RPM_PATH/$OS$major_version/base/openssl directory. Exiting...${RESET}"
                exit 1
            fi
            return 0
        fi

        if [ "$ONLINE_CONNECTION" = true ]; then
            packages=("wget" "make" "gcc" "zlib1g-dev" "perl")
            total_packages=${#packages[@]}
            duration=${total_packages}  # Duration for the progress bar
            $PKG_MANAGER install $silent_output "${packages[@]}" 2>&1 >/dev/null &
            display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for OpenSSL. Exiting...${RESET}" "$duration"
        else
            deb_count=$(ls -1 "$RPM_PATH/$OS$major_version/base/openssl"/*.deb 2>/dev/null | wc -l)
            if [ "$deb_count" -gt 0 ]; then
                duration=$deb_count
                $PKG_MANAGER install $silent_output "$RPM_PATH/$OS$major_version/base/openssl"/*.deb 2>&1 >/dev/null &
                display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for OpenSSL. Exiting...${RESET}" "$duration"
            else
                echo -e "${RED}ERROR: No DEB files found in $RPM_PATH/$OS$major_version/base/openssl directory. Exiting...${RESET}"
                exit 1
            fi
            deb_count=$(find "$RPM_PATH/$OS$major_version/postgres/common" -type f -name 'perl*.deb' | wc -l)
            duration=$deb_count
            $PKG_MANAGER install $silent_output "$RPM_PATH/$OS$major_version/postgres/common"/perl*.deb 2>&1 >/dev/null &
            display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install perl package for OpenSSL. Exiting...${RESET}" "$duration"
        fi
    fi
    openssl_version_tar="1.1.1w"
    cd /usr/local/src
    # wget https://www.openssl.org/source/openssl-1.1.1w.tar.gz
    cp "$RPM_PATH/python3/openssl/openssl-$openssl_version_tar.tar.gz" /usr/local/src
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to download openssl. Exiting...${RESET}"
        exit 1
    fi
    tar xf "openssl-$openssl_version_tar.tar.gz" 2>&1 >/dev/null &
    display_progress "$!" "spinner" "${RED}ERROR: Failed to untar openssl. Exiting...${RESET}"

    rm -f "openssl-$openssl_version_tar.tar.gz"
    cd "/usr/local/src/openssl-$openssl_version_tar"
    # Python is looking for lib directory in openssl
    mkdir "/usr/local/src/openssl-$openssl_version_tar/lib"
    ./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib no-shared zlib-dynamic 2>&1 >/dev/null &
    display_progress "$!" "spinner" "${RED}ERROR: An error occurred, preventing the OpenSSL installation from completing successfully. Exiting...${RESET}"

    make 2>&1 >/dev/null &
    display_progress "$!" "spinner" "${RED}ERROR: An error occurred, preventing the OpenSSL installation from completing successfully. Exiting...${RESET}"

    make install 2>&1 >/dev/null &
    display_progress "$!" "spinner" "${RED}ERROR: An error occurred, preventing the OpenSSL installation from completing successfully. Exiting...${RESET}"

    cp "/usr/local/src/openssl-$openssl_version_tar"/*.{so,so.1.0.0,a,pc} "/usr/local/src/openssl-$openssl_version_tar/lib" 2>&1 >/dev/null
    # display_progress "$!" "spinner" "${RED}ERROR: Could not found {so,so.1.0.0,a,pc} files, preventing the OpenSSL installation from completing successfully. Exiting...${RESET}"
    if [ "$OS" = "centos" ] && [ "$major_version" = "8" ]; then
        echo "export PATH=/usr/bin/pod2html:$PATH" >> ~/.bashrc
    fi
    echo "export PATH=/usr/bin:$PATH" >> ~/.bashrc
    echo "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH/usr/local/lib:/usr/local/lib64" >> ~/.bashrc
    echo "export LC_ALL=\"en_US.UTF-8\"" >> ~/.bashrc
    echo "export LDFLAGS=\"-L/usr/local/lib -Wl,-rpath,/usr/local/lib\"" >> ~/.bashrc
    source ~/.bashrc

    if ! command_exists "openssl"; then
        echo -e "${RED}::: openssl was not found.${RESET}"
        echo -e "${RED}::: Please make sure it is installed properly. Exiting...${RESET}"
        exit 1
    fi
    # Check the OpenSSL version and verify it's at least 1.1.1
    openssl_version=$(openssl version | awk '{print $2}' | xargs)
    openssl_required_version="1.1.1"
    if [[ "$openssl_version" < "$openssl_required_version" ]]; then
        echo "::: OpenSSL version is $openssl_version, but at least version $openssl_required_version is required."
        echo -e "${RED}::: Please ensure you have the correct version of OpenSSL installed. Exiting...${RESET}"
        exit 1
    fi
    cd "$CURRENT_PATH"
    echo
    echo -e "${GREEN}::: OpenSSL has been installed.${RESET}"
}

install_python310() {
    local packages=()
    local total_packages=0
    local duration=${total_packages}  # Duration for the progress bar
    if ! command_exists "openssl"; then
        install_openssl
    else
        # Define the minimum required OpenSSL version
        openssl_required_version="1.1.1"
        openssl_version=$(openssl version | awk '{print $2}' | xargs)

        if [[ "$openssl_version" < "$openssl_required_version" ]]; then
            install_openssl
        else
            echo -e "${GREEN}::: OpenSSL version is at least $openssl_required_version${RESET}"
        fi
    fi

    if [ "$OS" = "centos" ]; then
        #if ! command_exists "python3"; then
        if ! python3 -c 'import sys; exit(not (sys.version_info >= (3, 10)))'; then
            echo "::: Installing Python 3.10..."
            if [[ "$major_version" = "8" || "$major_version" = "9" || "$major_version" = "10" ]]; then
                if [ "$ONLINE_CONNECTION" = true ]; then
                    packages=("wget" "yum-utils" "make" "gcc" "openssl-devel" "bzip2-devel" "libffi-devel" "zlib-devel")
                    total_packages=${#packages[@]}
                    duration=${total_packages}  # Duration for the progress bar
                    $PKG_MANAGER groupinstall -y "Development Tools" 2>&1 >/dev/null &
                    $PKG_MANAGER --enablerepo=appstream install $silent_output "${packages[@]}" 2>&1 >/dev/null &
                    display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for python3. Exiting...${RESET}" "$duration"
                else
                    num_rpms=$(find "$RPM_PATH/$OS$major_version"/base/python3/*.rpm -maxdepth 1 -type f -name "*.rpm" | wc -l)
                    # Calculate the duration based on the number of RPM files
                    duration="$num_rpms"

                    $PKG_MANAGER localinstall $silent_output --nobest --disablerepo=* "$RPM_PATH/$OS$major_version"/base/python3/*.rpm 2>&1 >/dev/null &
                    display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for python3. Exiting...${RESET}" "$duration"
                fi

                #cd /usr/local/src
                #curl -O https://www.python.org/ftp/python/3.10.12/Python-3.10.12.tgz
                ###
                #tar -xvf Python-3.10.12.tgz
                #cd Python-3.10.12
                #./configure --enable-optimizations
                #make -j$(nproc)
                #sudo make altinstall 2>&1 >/dev/null &
                #display_progress "$!" "spinner" "${RED}ERROR: An error occurred, preventing the Python3.10 installation from completing successfully. Exiting...${RESET}"

                #rm -f ../Python-3.10.12.tgz
                #sudo alternatives --install /usr/bin/python python /usr/local/bin/python3 1
                #sudo alternatives --set python /usr/local/bin/python3

                # cd /usr/local/src
                # wget https://www.python.org/ftp/python/3.10.13/Python-3.10.13.tgz
                # cp "$RPM_PATH/python3/Python-$PYTHON_VERSION.tgz" /usr/local/src
                # if [ $? -ne 0 ]; then
                #     echo -e "${RED}ERROR: Failed to copy Python 3.10 from $RPM_PATH/python3/ directory. Exiting...${RESET}"
                #     exit 1
                # fi
                # tar xzf Python-$PYTHON_VERSION.tgz 2>&1 >/dev/null &
                # display_progress "$!" "spinner" "${RED}ERROR: Failed to untar Python-3.10. Exiting...${RESET}"

                # rm -f Python-$PYTHON_VERSION.tgz
                # cd Python-$PYTHON_VERSION
                # export PATH=$PATH:/usr/local/bin
                # ./configure --with-system-ffi --with-computed-gotos --enable-loadable-sqlite-extensions 2>&1 >/dev/null &
                # display_progress "$!" "spinner" "${RED}ERROR: An error occurred, preventing the Python 3.10 installation from completing successfully. Exiting...${RESET}"
                # make -j "$(nproc)" 2>&1 >/dev/null &
                # display_progress "$!" "spinner" "${RED}ERROR: An error occurred, preventing the Python 3.10 installation from completing successfully. Exiting...${RESET}"
                # make altinstall 2>&1 >/dev/null &
                # display_progress "$!" "spinner" "${RED}ERROR: An error occurred, preventing the Python 3.10 installation from completing successfully. Exiting...${RESET}"
            elif [ "$major_version" = "7" ]; then
                if [ "$ONLINE_CONNECTION" = true ]; then
                    packages=("yum-utils" "openssl-devel" "bzip2-devel" "libffi-devel" "zlib-devel" "ncurses-devel" "gdbm-devel" "xz-devel" "sqlite-devel" "tk-devel" "uuid-devel" "readline-devel")
                    total_packages=${#packages[@]}
                    duration=${total_packages}  # Duration for the progress bar
                    $PKG_MANAGER install $silent_output "${packages[@]}" 2>&1 >/dev/null &
                    display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for python3. Exiting...${RESET}" "$duration"
                else
                    num_rpms=$(find "$RPM_PATH/$OS$major_version"/base/python3/*.rpm -maxdepth 1 -type f -name "*.rpm" | wc -l)
                    # Calculate the duration based on the number of RPM files
                    duration="$num_rpms"

                    $PKG_MANAGER localinstall $silent_output --nobest --disablerepo=* "$RPM_PATH/$OS$major_version"/base/python3/*.rpm 2>&1 >/dev/null &
                    display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for python3. Exiting...${RESET}" "$duration"
                fi
                cd /usr/local/src
                cp "$RPM_PATH/python3/Python-$PYTHON_VERSION.tgz" /usr/local/src
                if [ $? -ne 0 ]; then
                    echo -e "${RED}ERROR: Failed to copy Python 3.10 from $RPM_PATH/python3/. Exiting...${RESET}"
                    exit 1
                fi
                tar xf Python-$PYTHON_VERSION.tgz 2>&1 >/dev/null &
                display_progress "$!" "spinner" "${RED}ERROR: Failed to untar Python-3.10. Exiting...${RESET}"

                rm -f Python-$PYTHON_VERSION.tgz
                cd /usr/local/src/Python-$PYTHON_VERSION
                export PATH=$PATH:/usr/local/bin
                # make clean && make distclean 2>&1 >/dev/null &
                # display_progress "$!" "spinner" "${RED}ERROR: An error occurred, preventing the Python 3.10 installation from completing successfully. Exiting...${RESET}"
                ./configure --enable-optimizations --with-openssl=/usr/local/src/openssl-1.1.1w/ 2>&1 >/dev/null &
                display_progress "$!" "spinner" "${RED}ERROR: An error occurred, preventing the Python 3.10 installation from completing successfully. Exiting...${RESET}"
                make altinstall 2>&1 >/dev/null &
                display_progress "$!" "spinner" "${RED}ERROR: An error occurred, preventing the Python 3.10 installation from completing successfully. Exiting...${RESET}"
            fi
            ln -s /usr/local/bin/python3 /usr/bin/python3
            echo
            echo -e "${GREEN}::: Python 3.10 has been installed.${RESET}"
        fi
    elif [ "$OS" = "ubuntu" ]; then
        if ! command_exists "python3"; then
            echo "::: Installing Python 3.10..."
            if [ "$ONLINE_CONNECTION" = true ]; then
                packages=("wget" "make" "build-essential" "zlib1g-dev" "libncurses5-dev" "libgdbm-dev" "libnss3-dev" "libssl-dev" "libreadline-dev" "libffi-dev" "libsqlite3-dev" "libbz2-dev" "liblzma-dev" "tk-dev" "uuid-dev")
                total_packages=${#packages[@]}
                duration=${total_packages}  # Duration for the progress bar
                confirm_and_update_packages

                # env DEBIAN_FRONTEND=noninteractive $PKG_MANAGER install $silent_output "${packages[@]}" 2>&1 >/dev/null &
                $PKG_MANAGER install $silent_output "${packages[@]}" &
                # if [ $? -ne 0 ]; then
                #     echo -e "${RED}ERROR: Failed to install dependencies packages for Python 3.10. Exiting...${RESET}"
                #     exit 1
                # fi
                display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for Python 3.10. Exiting...${RESET}" "$duration"
            else #???????????????????????????
                num_debs=$(find "$RPM_PATH/$OS$major_version"/base/python3/*.deb -maxdepth 1 -type f -name "*.deb" | wc -l)
                # Calculate the duration based on the number of RPM files
                duration="$num_debs"

                $PKG_MANAGER install $silent_output "$RPM_PATH/$OS$major_version"/base/python3/*.deb
                # display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for python3. Exiting...${RESET}" "$duration"
            fi
            cd /usr/local/src
            # wget https://www.python.org/ftp/python/3.10.13/Python-3.10.13.tgz
            cp "$RPM_PATH/python3/Python-$PYTHON_VERSION.tgz" /usr/local/src
            if [ $? -ne 0 ]; then
                echo -e "${RED}ERROR: Failed to copy Python 3.10 from $RPM_PATH/python3/. Exiting...${RESET}"
                exit 1
            fi
            tar xf "Python-$PYTHON_VERSION.tgz" 2>&1 >/dev/null &
            display_progress "$!" "spinner" "${RED}ERROR: Failed to untar Python-3.10. Exiting...${RESET}"

            rm -f "/usr/local/src/Python-$PYTHON_VERSION.tgz"
            cd "/usr/local/src/Python-$PYTHON_VERSION"
            export PATH=$PATH:/usr/local/bin
            ./configure --enable-optimizations 2>&1 >/dev/null &
            display_progress "$!" "spinner" "${RED}ERROR: An error occurred, preventing the Python 3.10 installation from completing successfully. Exiting...${RESET}"
            make -j "$(nproc)" 2>&1 >/dev/null &
            display_progress "$!" "spinner" "${RED}ERROR: An error occurred, preventing the Python 3.10 installation from completing successfully. Exiting...${RESET}"
            make altinstall 2>&1 >/dev/null &
            display_progress "$!" "spinner" "${RED}ERROR: An error occurred, preventing the Python 3.10 installation from completing successfully. Exiting...${RESET}"

            ln -s /usr/local/bin/python3 /usr/bin/python3
            echo
            echo -e "${GREEN}::: Python 3.10 has been installed.${RESET}"
        fi
    else
        echo -e "${RED}::: Unsupported distribution was detected, Python 3.10 installation cannot proceed. Exiting...${RESET}"
        exit 1
    fi

    if ! command_exists "python3"; then
        echo -e "${RED}::: python3 was not found.${RESET}"
        echo -e "${RED}::: Please make sure it's installed properly. Exiting...${RESET}"
        exit 1
    else
        echo -e "${GREEN}::: Python 3.10 is available.${RESET}"
    fi
    if ! command_exists "pip3"; then
        echo -e "${RED}::: pip3 was not found. Attempting to install it...${RESET}"

        if ! dnf install -y python3-pip -q >/dev/null 2>&1; then
                echo -e "${RED}::: Failed to install pip3. Please check your DNF configuration or internet connection.${RESET}"
                exit 1
        fi

        echo -e "${GREEN}::: pip3 was successfully installed.${RESET}"
    fi
    if [ "$ONLINE_CONNECTION" = true ]; then
        python3 -m pip install --upgrade pip 2>&1 >/dev/null
        python3 -m pip install virtualenv 2>&1 >/dev/null &
        display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install virtualenv package using pip3. Exiting...${RESET}" "1"
    else
        python3 -m pip install "$RPM_PATH"/python3/wheels/pip3/*.whl 2>&1 >/dev/null
        whl_count=$(ls -1 "$RPM_PATH"/python3/wheels/virtualenv/*.whl 2>/dev/null | wc -l)
        if [ "$whl_count" -gt 0 ]; then
            duration=$((whl_count + 1))
        else
            echo -e "${RED}ERROR: No wheels files found in $RPM_PATH/python3/wheels/virtualenv directory. Exiting...${RESET}"
            exit 1
        fi
        python3 -m pip install "$RPM_PATH"/python3/wheels/virtualenv/*.whl 2>&1 >/dev/null &
        display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install virtualenv package using pip3. Exiting...${RESET}" "$duration"

        python3 -m pip install "$RPM_PATH"/python3/wheels/gnureadline*.whl 2>&1 >/dev/null
    fi
    cd "$CURRENT_PATH"
}

install_postgresql() { ### Postgres using files
    # https://www.postgresql.org/download/linux/redhat/
    echo "::: Installing PostgreSQL $PG_VERSION..."
    # read -p "Enter port for PostgreSQL installation: " DB_PORT
    local num_rpms=0
    local duration=0
    local pg_common_dir="$RPM_PATH/$OS$major_version/postgres/common"
    if [ "$OS" = "centos" ]; then
        # Install the PostgreSQL packages for CentOS/RHEL
        # Calculate the number of RPM files in the directory
        # num_rpms=$(find "$pg_common_dir" -maxdepth 1 -type f -name "*.rpm" | wc -l)
        # duration="$num_rpms"
        # $PKG_MANAGER $silent_output localinstall --nobest --disablerepo=* "$pg_common_dir"/*.rpm 2>&1 >/dev/null &
        # display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install PostgreSQL $PG_VERSION. Exiting...${RESET}" "$duration"
        $PKG_MANAGER install $silent_output -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-10-x86_64/pgdg-redhat-repo-latest.noarch.rpm 2>&1 >/dev/null
        #$PKG_MANAGER -qy module disable postgresql
        $PKG_MANAGER install $silent_output -y postgresql15-server 2>&1 >/dev/null
        # for version in "${PG_VERSIONS_LIST[@]}"; do
        #     local pg_version_dir="$RPM_PATH/$OS$major_version/postgres/$version"
        #     num_rpms=$(find "$pg_version_dir" -maxdepth 1 -type f -name "*.rpm" | wc -l)
        #     duration="$num_rpms"
        #     $PKG_MANAGER $silent_output localinstall --nobest --disablerepo=* "$pg_version_dir"/*.rpm 2>&1 >/dev/null &
        #     display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install PostgreSQL $version. Exiting...${RESET}" "$duration"
        # done

        # Loop until a valid and empty PostgreSQL data directory is provided
        while true; do
            read -p "Please enter the PostgreSQL data directory path: " PG_DATA
            # Validate the path syntax (check if it starts with / for absolute paths)
            if [[ "$PG_DATA" =~ ^/ ]]; then
                if [ -z "$(ls -A "$PG_DATA" 2>/dev/null)" ]; then
                    echo -e "${GREEN}::: The provided path is a valid and empty PostgreSQL data directory.${RESET}"
                    break
                else
                    echo -e "${RED}ERROR: The provided path is a valid PostgreSQL data directory, but it is not empty. Please provide an empty directory.${RESET}"
                fi
            else
                echo -e "${RED}ERROR: The provided path is not a valid PostgreSQL data directory. Please try again.${RESET}"
            fi
        done

        mkdir -p $PG_DATA &
        display_progress "$!" "spinner" "${RED}ERROR: Failed to make PostgreSQL data directory. Exiting...${RESET}"

        chown -R postgres:postgres $PG_DATA
        chmod 0700 $PG_DATA

        #POSTGRES_BIN_DIR=$(dirname $(rpm -ql postgresql$PG_VERSION-server.x86_64 | grep initdb | grep -v share) 2>/dev/null || pg_config --bindir 2>/dev/null)
        POSTGRES_BIN_DIR=$(dirname "$(command -v pg_ctl 2>/dev/null || find /usr /opt -type f -name 'pg_ctl' 2>/dev/null | head -n 1)")

        echo "export PATH=$POSTGRES_BIN_DIR:\$PATH" >> ~/.bashrc
        source ~/.bashrc
        echo "export PATH=$POSTGRES_BIN_DIR:\$PATH" >> ~/.bash_profile
        source ~/.bash_profile

        # Check if pg_config returned a valid path
        if [ -n "$POSTGRES_BIN_DIR" ]; then
            echo -e "${GREEN}::: PostgreSQL binary directory: $POSTGRES_BIN_DIR${RESET}"
        else
            echo -e "${RED}ERROR: PostgreSQL binary directory not found. Exiting...${RESET}"
            exit 1
        fi

        # chmod +x "$CURRENT_PATH/scripts/postgresql-$PG_VERSION-setup"

        # initdb_output=$("$CURRENT_PATH/scripts/postgresql-$PG_VERSION-setup" initdb)
        initdb_output=$(su - postgres -c "export LANG=en_US.UTF-8; export LC_ALL=en_US.UTF-8; $POSTGRES_BIN_DIR/initdb -D $PG_DATA" 2>&1)
        if [ $? -ne 0 ]; then
            # Convert both the output and error message to lowercase
            initdb_output_lower=$(echo "$initdb_output" | tr '[:upper:]' '[:lower:]')
            error_message="data directory is not empty"
            # Check if the initdb_output contains the error message (case-insensitive)
            if [[ "$initdb_output_lower" == *"$error_message"* ]]; then
                echo -e "${RED}ERROR: Data directory $PG_DATA is not empty! Exiting...${RESET}"
                exit 1
            else
                echo -e "${RED}ERROR: Failed to initialize PostgreSQL server. Exiting...${RESET}"
                exit 1
            fi
        fi

        if [ "$major_version" = "8" ]; then
            sed -i '/^KillSignal.*/a ExecStopPost=+systemctl daemon-reload' "/usr/lib/systemd/system/postgresql-$PG_VERSION.service"
        fi

        sed -i "/^PGDATA[^ ]*/c PGDATA=$PG_DATA" "/var/lib/pgsql/.bash_profile"
        sed -i "/Environment=PGDATA/c Environment=PGDATA=$PG_DATA" "/usr/lib/systemd/system/postgresql-$PG_VERSION.service"
        systemctl daemon-reload

        echo -e "${GREEN}::: PostgreSQL $PG_VERSION has been installed.${RESET}"

        echo "::: Configuring PostgreSQL files..."
        # configure pg_hba.conf and postgresql.conf (listen_addresses, port)
        # sh -c "printf 'host    %-15s%-15s%-20s%s\n' \"$DB_NAME_PG_HBA\" \"all\" \"$HOST_IP/32\" \"scram-sha-256\" >> \"$PG_DATA/pg_hba.conf\""
        sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '$LISTEN_ADDRESSES'/" "$PG_DATA/postgresql.conf"
        sed -i "s/max_connections = 100/max_connections = 300/" "$PG_DATA/postgresql.conf"
        # sed -i "s/#port = 5432/port = $DB_PORT/" "$PG_DATA/postgresql.conf"

        systemctl enable "postgresql-$PG_VERSION"
        systemctl start "postgresql-$PG_VERSION" &
        display_progress "$!" "spinner" "${RED}ERROR: Failed to start PostgreSQL server. Exiting...${RESET}"
    elif [ "$OS" = "ubuntu" ]; then
        # Calculate the number of DEB files in the directory
        num_rpms=$(find "$pg_common_dir" -maxdepth 1 -type f -name "*.deb" | wc -l)
        # Calculate the duration based on the number of RPM files
        duration="$num_rpms"
        $PKG_MANAGER install $silent_output --allow-downgrades "$pg_common_dir"/*.deb 2>&1 >/dev/null &
        display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install PostgreSQL $PG_VERSION. Exiting...${RESET}" "$duration"

        for version in "${PG_VERSIONS_LIST[@]}"; do
            local pg_version_dir="$RPM_PATH/$OS$major_version/postgres/$version"
            num_rpms=$(find "$pg_version_dir" -maxdepth 1 -type f -name "*.deb" | wc -l)
            duration="$num_rpms"
            $PKG_MANAGER install $silent_output --allow-downgrades "$pg_version_dir"/*.deb 2>&1 >/dev/null &
            display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install PostgreSQL $version. Exiting...${RESET}" "$duration"
        done

                num_rpms=$(find "$pg_version_dir" -maxdepth 1 -type f -name "*.dev" | wc -l)
        duration="$num_rpms"
        $PKG_MANAGER install $silent_output --allow-downgrades "$pg_version_dir"/*.deb 2>&1 >/dev/null &
        display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install PostgreSQL $PG_VERSION. Exiting...${RESET}" "$duration"

        # Loop until a valid and empty PostgreSQL data directory is provided
        while true; do
            read -p "Please enter the PostgreSQL data directory path: " PG_DATA
            # Validate the path syntax (check if it starts with / for absolute paths)
            if [[ "$PG_DATA" =~ ^/ ]]; then
                if [ -z "$(ls -A "$PG_DATA")" ]; then
                    echo -e "${GREEN}::: The provided path is a valid and empty PostgreSQL data directory.${RESET}"
                    break
                else
                    echo -e "${RED}ERROR: The provided path is a valid PostgreSQL data directory, but it is not empty. Please provide an empty directory.${RESET}"
                fi
            else
                echo -e "${RED}ERROR: The provided path is not a valid PostgreSQL data directory. Please try again.${RESET}"
            fi
        done

        systemctl disable postgresql
        systemctl stop postgresql &
        display_progress "$!" "spinner" "${RED}ERROR: Failed to stop PostgreSQL server. Exiting...${RESET}"

        mkdir -p $PG_DATA &
        display_progress "$!" "spinner" "${RED}ERROR: Failed to make PostgreSQL data directory. Exiting...${RESET}"

        chown -R postgres:postgres $PG_DATA
        chmod 0700 $PG_DATA

        POSTGRES_BIN_DIR=$(dirname $(find /usr -name initdb | grep $PG_VERSION) 2>/dev/null || pg_config --bindir 2>/dev/null)

        # Check if pg_config returned a valid path
        if [ -n "$POSTGRES_BIN_DIR" ]; then
            echo -e "${GREEN}::: PostgreSQL binary directory: $POSTGRES_BIN_DIR${RESET}"
        else
            echo -e "${RED}ERROR: PostgreSQL binary directory not found. Exiting...${RESET}"
            exit 1
        fi

        # 'main' is the default
        pg_dropcluster $PG_VERSION main
        pg_createcluster $PG_VERSION $APP_DB_NAME -d $PG_DATA -p $DB_PORT &
        display_progress "$!" "spinner" "${RED}ERROR: Failed to create PostgreSQL instance. Exiting...${RESET}"

        # Loop through the list and exclude the specified version
        for version in "${PG_VERSIONS_LIST[@]}"; do
            if [ "$version" -ne "$PG_VERSION" ]; then
                pg_version_dir="$RPM_PATH/$OS$major_version/postgres/$version"
                num_rpms=$(find "$pg_version_dir" -maxdepth 1 -type f -name "*.deb" | wc -l)
                duration="$num_rpms"
                $PKG_MANAGER install $silent_output "$pg_version_dir"/*.deb 2>&1 >/dev/null &
                display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install PostgreSQL $version. Exiting...${RESET}" "$duration"

                systemctl stop postgresql@$version-main
                systemctl disable postgresql@$version-main
            fi
        done

        echo -e "${GREEN}::: PostgreSQL $PG_VERSION has been installed.${RESET}"
        echo "::: Configuring PostgreSQL files..."
        # sh -c "printf 'host    %-15s%-15s%-20s%s\n' \"$DB_NAME_PG_HBA\" \"all\" \"$HOST_IP/32\" \"scram-sha-256\" >> \"$pg_conf_path_ubuntu/pg_hba.conf\""
        sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '$LISTEN_ADDRESSES'/" "$pg_conf_path_ubuntu/postgresql.conf"
        sed -i "s/max_connections = 100/max_connections = 300/" "$pg_conf_path_ubuntu/postgresql.conf"
        # sed -i "s/#port = 5432/port = $DB_PORT/" "$pg_conf_path_ubuntu/postgresql.conf"

        systemctl enable postgresql@$PG_VERSION-$APP_DB_NAME
        systemctl start postgresql@$PG_VERSION-$APP_DB_NAME &
        display_progress "$!" "spinner" "${RED}ERROR: Failed to start PostgreSQL server. Exiting...${RESET}"
    else
        echo -e "${RED}::: Unsupported distribution was detected, PostgreSQL installation cannot proceed. Exiting...${RESET}"
        exit 1
    fi
    echo -e "${GREEN}::: PostgreSQL files have been configured.${RESET}"
}

function confirm_skip_installation() {
    while true; do
        read -p "Do you want to continue with the installation of $APP_DB_NAME without Oracle driver? (y/n): " skip_installation
        if [ "$skip_installation" = "y" ] || [ "$skip_installation" = "Y" ]; then
            echo 0
            break
        elif [ "$skip_installation" = "n" ] || [ "$skip_installation" = "N" ]; then
            echo 1
            break
        else
            echo "Please enter 'y' or 'n' only."
        fi
    done
}

install_oracle_driver() { ### Oracle using files
    # yum install libaio / apt-get install libaio1
    echo "::: Installing Oracle driver..."
    # Instructions to download Oracle driver: https://oracle.github.io/odpi/doc/installation.html#linux
    if [ "$OS" = "centos" ]; then
        # wget https://download.oracle.com/otn_software/linux/instantclient/2111000/oracle-instantclient-basic-21.11.0.0.0-1.x86_64.rpm
        # wget https://download.oracle.com/otn_software/linux/instantclient/2111000/oracle-instantclient-basic-21.11.0.0.0-1.el8.x86_64.rpm
        # wget https://download.oracle.com/otn_software/linux/instantclient/2112000/el9/oracle-instantclient-basic-21.12.0.0.0-1.el9.x86_64.rpm
        $PKG_MANAGER localinstall $silent_output --nobest --disablerepo=* "$RPM_PATH/$OS$major_version"/base/oracle_driver/oracle-instantclient-basic-*.rpm 2>&1 >/dev/null
        if [ $? -ne 0 ]; then
            echo -e "${RED}ERROR: Failed to install Oracle driver.${RESET}"
            echo "::: You can install the Oracle driver later by https://oracle.github.io/odpi/doc/installation.html#linux"
            confirm_result=$(confirm_skip_installation)
            if [ "$confirm_result" -eq 0 ]; then
                echo "::: Continuing with the installation..."
                return 0
            elif [ "$confirm_result" -eq 1 ]; then
                echo -e "${BLUE}::: Exiting...${RESET}"
                exit 1
            fi
        fi

        oracle_directory="/usr/lib/oracle"
        # Use ls to list the contents of the directory, sort by modification time (-t), and awk to filter by pattern
        oracle_basic_newest_folder=$(ls -t "$oracle_directory" | awk '/^[0-9]+(\.[0-9]+)?$/ {print; exit}')
        if [ -z "$oracle_basic_newest_folder" ]; then
            echo -e "${RED}ERROR: Something went wrong in installation. Oracle folder not found in $oracle_directory.${RESET}"
            echo "::: You can install the Oracle driver later by https://oracle.github.io/odpi/doc/installation.html#linux"
            confirm_result=$(confirm_skip_installation)
            if [ "$confirm_result" -eq 0 ]; then
                echo "::: Continuing with the installation..."
                return 0
            elif [ "$confirm_result" -eq 1 ]; then
                echo -e "${BLUE}::: Exiting...${RESET}"
                exit 1
            fi
        fi

        echo "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$oracle_directory/$oracle_basic_newest_folder/client64/lib" >> ~/.bashrc
        source ~/.bashrc
    elif [ "$OS" = "ubuntu" ]; then
        if ! command_exists "unzip"; then
            echo "::: Installing unzip package..."
            if [ "$ONLINE_CONNECTION" = true ]; then
                confirm_and_update_packages
                $PKG_MANAGER install $silent_output unzip 2>&1 >/dev/null

                # Download Oracle Instant Client ZIP file
                # wget https://download.oracle.com/otn_software/linux/instantclient/2111000/instantclient-basic-linux.x64-21.11.0.0.0dbru.zip
            else
                env DEBIAN_FRONTEND=noninteractive dpkg -i "$RPM_PATH/$OS$major_version"/base/unzip*.deb 2>&1 >/dev/null
            fi
            if [ $? -ne 0 ]; then
                echo "WARNING: Installation of Oracle driver requires 'unzip', which is not installed."
                echo "Please install the Oracle driver manually: https://oracle.github.io/odpi/doc/installation.html#linux"
                while true; do
                    read -p "Do you want to continue the installation without Oracle driver? (y/n): " continue_installation
                    case $continue_installation in
                        [Yy]*)
                            echo "::: Skipping 'unzip' installation and Oracle driver installation."
                            return 0
                            ;;
                        [Nn]*)
                            echo -e "${BLUE}::: Installation aborted. Exiting...${RESET}"
                            exit 1
                            ;;
                        *)
                            echo "Please enter 'y' or 'n' only."
                            ;;
                    esac
                done
            else
                echo -e "${GREEN}::: unzip has been installed.${RESET}"
            fi
            rm -f ./unzip*.deb 2>&1 >/dev/null
        fi
        # Extract the contents (you may need unzip installed)
        cp "$RPM_PATH/$OS$major_version"/base/oracle_driver/instantclient-basic-linux*.zip ./
        if [ $? -ne 0 ]; then
            echo -e "${RED}ERROR: Failed to copy Oracle driver from $RPM_PATH/$OS$major_version/base/oracle_driver/.${RESET}"
            echo "::: You can install the Oracle driver later by https://oracle.github.io/odpi/doc/installation.html#linux"
            confirm_result=$(confirm_skip_installation)
            if [ "$confirm_result" -eq 0 ]; then
                echo "::: Continuing with the installation..."
                return 0
            elif [ "$confirm_result" -eq 1 ]; then
                echo -e "${BLUE}::: Exiting...${RESET}"
                exit 1
            fi
        fi

        unzip instantclient-basic-linux.x64-21.11.*.zip >/dev/null
        if [ $? -ne 0 ]; then
            echo -e "${RED}ERROR: Failed to unzip Oracle driver.${RESET}"
            echo "::: You can install the Oracle driver later by https://oracle.github.io/odpi/doc/installation.html#linux"
            confirm_result=$(confirm_skip_installation)
            if [ "$confirm_result" -eq 0 ]; then
                echo "::: Continuing with the installation..."
                return 0
            elif [ "$confirm_result" -eq 1 ]; then
                echo -e "${BLUE}::: Exiting...${RESET}"
                exit 1
            fi
        fi
        mkdir -p /opt/oracle
        mv instantclient_21_11 /opt/oracle/
        if [ $? -ne 0 ]; then
            echo -e "${RED}ERROR: Failed to move Oracle driver to /opt/oracle/.${RESET}"
            echo "::: The Oracle driver installation was not completed."
            echo "::: Continuing with the app installation..."
            return 0
        fi
        echo "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/oracle/instantclient_21_11" >> ~/.bashrc
        source ~/.bashrc
        rm -f ./instantclient-basic-linux.x64-21.11.*.zip
    else
        echo -e "${RED}ERROR: Unsupported distribution. Exiting...${RESET}"
        exit 1
    fi
    echo -e "${GREEN}::: Oracle driver has been installed.${RESET}"
}

install_backend_folder() {
    cd "$backend_path"

    local monitors_schema_name="app_clusterapp_monitor"
    local pg_home_dir=$(su - postgres -c "pwd")
    local DUMP_MONITOR_FILE="$pg_home_dir/monitors/$monitors_schema_name.sql"
    local DUMP_MONITORS_TABLE_FILE="$pg_home_dir/monitors/rp_monitors_table.sql"
    local DUMP_MONITOR_COLUMNS_TABLE_FILE="$pg_home_dir/monitors/rp_monitor_columns_table.sql"
    local DUMP_MONITOR_TASK_DEFINITIONS_TABLE_FILE="$pg_home_dir/monitors/monitor_task_definitions.sql"
    chown -R postgres:postgres "${CURRENT_PATH%/}/scripts/monitors"
    cp -a "${CURRENT_PATH%/}/scripts/monitors" "$pg_home_dir"
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}WARNING: Failed to copy $CURRENT_PATH/scripts/monitors to $pg_home_dir.${RESET}"
    fi

    while true; do
        read -p "Select the SSH port to be used on your machine: " SSH_PORT
        # Check if input is a positive number or zero
        if [[ "$SSH_PORT" =~ ^[0-9]+$ ]]; then
            break  # Valid input, exit the loop
        else
            echo -e "${RED}Invalid input. Please enter a SSH port.${RESET}"
        fi
    done

    while true; do
        read -p "Enter root password or path to private key for ClusterApp: " CREDENTIAL
        if [[ -n "$CREDENTIAL" ]]; then
            # Check if the input is a file (assumed to be a private key)
            if [[ -f "$CREDENTIAL" ]]; then
                # Attempt SSH connection using the private key
                ssh_check=$(ssh -o BatchMode=yes -i "$CREDENTIAL" root@$hostname 2>&1)
                if [[ $? -eq 0 ]]; then
                    echo "${GREEN}Private key authentication successful.${RESET}"
                    private_key=true
                    private_key_content=$(cat "$CREDENTIAL")
                    break  # Valid private key, exit the loop
                else
                    echo -e "${RED}Private key authentication failed. Please enter a valid private key.${RESET}"
                fi
            else
                # Assume it's a password if not a file
                # You would typically use the password in your script as needed

                # Prompt user to confirm the password
                read -p "Confirm the entered password: " CONFIRM_PASSWORD
                if [[ "$CREDENTIAL" == "$CONFIRM_PASSWORD" ]]; then
                    echo -e "${GREEN}::: Password confirmed.${RESET}"
                    private_key=false
                    break  # Valid password, exit the loop
                else
                    echo -e "${RED}Passwords do not match. Please re-enter.${RESET}"
                fi
            fi
        else
            echo -e "${RED}Invalid input. Please enter a root password or path to a private key.${RESET}"
        fi
    done

    # Get an organization name
    while true; do
        read -p "Enter organization name for ClusterApp: " ORG_NAME
        # Check if the organization name is not empty
        if [[ -n "$ORG_NAME" ]]; then
            break  # Valid input, exit the loop
        else
            echo -e "${RED}Invalid input. Please enter an organization name.${RESET}"
        fi
    done

    local forbidden_chars="!@#$%^&*()_+={}[]|:;'<>?~\`"
    # Get a valid PostgreSQL username
    while true; do
        read -p "Enter user name for $APP_DB_NAME database: " DB_USERNAME
        if [[ "$DB_USERNAME" =~ ^[a-zA-Z0-9_]+$ ]]; then
            break  # Valid input, exit the loop
        else
            echo -e "${RED}Invalid input. Please enter a username with letters, digits, and underscores only.${RESET}"
        fi
    done

    # Input validation loop for PWD_USERNAME
    while true; do
        read -s -p "Enter password for $DB_USERNAME user: " PWD_USERNAME
        # Check if the password is not empty and contains only allowed characters
        if [[ -n "$PWD_USERNAME" && ! "$PWD_USERNAME" =~ [^a-zA-Z0-9$forbidden_chars] ]]; then
            echo
            # Prompt user to confirm the password
            read -s -p "Confirm the entered password: " CONFIRM_PASSWORD
            echo
            if [[ "$PWD_USERNAME" == "$CONFIRM_PASSWORD" ]]; then
                echo -e "${GREEN}::: Password confirmed.${RESET}"
                break  # Valid password, exit the loop
            else
                echo -e "${RED}Passwords do not match. Please re-enter.${RESET}"
            fi
        else
            echo -e "${RED}Invalid input. Please enter a valid password with letters, digits, and some special characters.${RESET}"
        fi
    done

    # housekeeper_short_retention
    while true; do
        read -p "Enter the short retention period for ClusterApp data retention (in days): " housekeeper_short_retention
        # Check if input is a positive number or zero
        if [[ "$housekeeper_short_retention" =~ ^[0-9]+$ ]]; then
            break  # Valid input, exit the loop
        else
            echo -e "${RED}Invalid input. Please enter a positive number or zero.${RESET}"
        fi
    done

    # housekeeper_long_retention
    while true; do
        read -p "Enter the long retention period for ClusterApp data retention (in days): " housekeeper_long_retention
        # Check if input is a positive number or zero
        if [[ "$housekeeper_long_retention" =~ ^[0-9]+$ ]]; then
            if (( housekeeper_long_retention > housekeeper_short_retention )); then
                break  # Valid input, exit the loop
            else
                echo -e "${RED}Invalid input. Long retention period must be greater than short retention period.${RESET}"
            fi
        else
            echo -e "${RED}Invalid input. Please enter a positive number or zero.${RESET}"
        fi
    done

    # Prompt and validate max notifications per hour
    while true; do
        read -p "Enter the max notifications per hour: " max_notifications_per_hour
        # Check if input is a positive number or zero
        if [[ "$housekeeper_long_retention" =~ ^[0-9]+$ ]]; then
            break  # Valid input, exit the loop
        else
            echo -e "${RED}Invalid input. Please enter a positive number or zero.${RESET}"
        fi
    done

    # Explicit public ip of machine should go first, for fail-safe, and duplicate the same for ssl connections!
    if [ "$OS" = "centos" ]; then
        sh -c "printf 'hostssl    %-15s%-15s%-20s%s\n' \"$DB_NAME_PG_HBA\" \"$DB_USERNAME\" \"$ip_address/32\" \"scram-sha-256\" >> \"$PG_DATA/pg_hba.conf\""
        sh -c "printf 'hostssl    %-15s%-15s%-20s%s\n' \"$DB_NAME_PG_HBA\" \"$DB_USERNAME\" \"$HOST_IP/32\" \"scram-sha-256\" >> \"$PG_DATA/pg_hba.conf\""
        sh -c "printf 'host    %-15s%-15s%-20s%s\n' \"$DB_NAME_PG_HBA\" \"$DB_USERNAME\" \"$ip_address/32\" \"scram-sha-256\" >> \"$PG_DATA/pg_hba.conf\""
        sh -c "printf 'host    %-15s%-15s%-20s%s\n' \"$DB_NAME_PG_HBA\" \"$DB_USERNAME\" \"$HOST_IP/32\" \"scram-sha-256\" >> \"$PG_DATA/pg_hba.conf\""
    elif [ "$OS" = "ubuntu" ]; then
        sh -c "printf 'hostssl    %-15s%-15s%-20s%s\n' \"$DB_NAME_PG_HBA\" \"$DB_USERNAME\" \"$ip_address/32\" \"scram-sha-256\" >> \"$pg_conf_path_ubuntu/pg_hba.conf\""
        sh -c "printf 'hostssl    %-15s%-15s%-20s%s\n' \"$DB_NAME_PG_HBA\" \"$DB_USERNAME\" \"$HOST_IP/32\" \"scram-sha-256\" >> \"$pg_conf_path_ubuntu/pg_hba.conf\""
        sh -c "printf 'host    %-15s%-15s%-20s%s\n' \"$DB_NAME_PG_HBA\" \"$DB_USERNAME\" \"$ip_address/32\" \"scram-sha-256\" >> \"$pg_conf_path_ubuntu/pg_hba.conf\""
        sh -c "printf 'host    %-15s%-15s%-20s%s\n' \"$DB_NAME_PG_HBA\" \"$DB_USERNAME\" \"$HOST_IP/32\" \"scram-sha-256\" >> \"$pg_conf_path_ubuntu/pg_hba.conf\""
    fi

    su - postgres -c "psql -p $DB_PORT -c 'SELECT pg_reload_conf();'" 2>&1 >/dev/null
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to reload the pg_hba.conf file. Exiting...${RESET}"
        exit 1
    fi
    su - postgres -c "psql -p $DB_PORT -c 'CREATE USER \"$DB_USERNAME\" WITH LOGIN ENCRYPTED PASSWORD '\''$PWD_USERNAME'\'';'"
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to create the database user $DB_USERNAME. Exiting...${RESET}"
        exit 1
    fi
    su - postgres -c "psql -p $DB_PORT -c 'CREATE DATABASE \"$APP_DB_NAME\" WITH OWNER \"$DB_USERNAME\";'"
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to create the database $APP_DB_NAME. Exiting...${RESET}"
        exit 1
    fi
    su - postgres -c "psql -p $DB_PORT -c 'GRANT CONNECT ON DATABASE \"$APP_DB_NAME\" TO \"$DB_USERNAME\";'"
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to grant the database user $DB_USERNAME connect on $APP_DB_NAME. Exiting...${RESET}"
        exit 1
    fi
    su - postgres -c "psql -p $DB_PORT -d \"$APP_DB_NAME\" -c 'CREATE SCHEMA $monitors_schema_name AUTHORIZATION \"$DB_USERNAME\";'"
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to create the schema $monitors_schema_name. Exiting...${RESET}"
        exit 1
    fi

    sed -i "s/OWNER TO postgres;/OWNER TO $DB_USERNAME;/g" "$DUMP_MONITOR_FILE"

    su - postgres -c "psql -p $DB_PORT -d \"$APP_DB_NAME\" -f \"$DUMP_MONITOR_FILE\""
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to build the schema $monitors_schema_name. Exiting...${RESET}"
        exit 1
    fi

    su - postgres -c "psql -p $DB_PORT -d \"$APP_DB_NAME\" -f \"$DUMP_MONITORS_TABLE_FILE\""
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}WARNING: Failed to insert data into $monitors_schema_name.rp_monitors table.${RESET}"
    fi

        su - postgres -c "psql -p $DB_PORT -d \"$APP_DB_NAME\" -f \"$DUMP_MONITOR_COLUMNS_TABLE_FILE\""
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}WARNING: Failed to insert data into $monitors_schema_name.rp_monitor_columns table.${RESET}"
    fi

        # this should come after all data imports
    su - postgres -c "psql -p $DB_PORT -d \"$APP_DB_NAME\" -c 'GRANT USAGE, CREATE ON SCHEMA public, $monitors_schema_name TO \"$DB_USERNAME\";'"
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to grant the database user $DB_USERNAME usage. Exiting...${RESET}"
        exit 1
    fi

        # grant read-write access on tables in schemas
        su - postgres -c "psql -p $DB_PORT -d \"$APP_DB_NAME\" -c 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public, $monitors_schema_name TO \"$DB_USERNAME\";'"
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to grant the database user $DB_USERNAME read-write access on tables. Exiting...${RESET}"
        exit 1
    fi

    echo -e "${GREEN}::: $APP_DB_NAME database and $DB_USERNAME user were created.${RESET}"

    echo "::: Setting up PostgreSQL connection for application..."
#    cp "$backend_path/core/settings/.env_placeholders" "$backend_path/core/settings/.env"
#    sed -i "s/'NAME': 'DB_PLACEHOLDER'/'NAME': '$APP_DB_NAME'/g" "$backend_path/core/settings/.env"
#    sed -i "s/'USER': 'USER_PLACEHOLDER'/'USER': '$DB_USERNAME'/g" "$backend_path/core/settings/.env"
#    sed -i "s/'PASSWORD': 'PWD_PLACEHOLDER'/'PASSWORD': '$PWD_USERNAME'/g" "$backend_path/core/settings/.env"
#    sed -i "s/'HOST': 'HOST_PLACEHOLDER'/'HOST': '$ip_address'/g" "$backend_path/core/settings/.env"
#    sed -i "s/'PORT': 'PORT_PLACEHOLDER'/'PORT': '$DB_PORT'/g" "$backend_path/core/settings/.env"

    cp "$backend_path/core/settings/.env_placeholders" "$backend_path/core/settings/.env"
    sed -i "s/DB_NAME=DB_PLACEHOLDER/DB_NAME=$APP_DB_NAME/g" "$backend_path/core/settings/.env"
    sed -i "s/DB_USER=USER_PLACEHOLDER/DB_USER=$DB_USERNAME/g" "$backend_path/core/settings/.env"
    sed -i "s/DB_PASSWORD=PWD_PLACEHOLDER/DB_PASSWORD=$PWD_USERNAME/g" "$backend_path/core/settings/.env"
    sed -i "s/DB_HOST=HOST_PLACEHOLDER/DB_HOST=$ip_address/g" "$backend_path/core/settings/.env"
    sed -i "s/DB_PORT=PORT_PLACEHOLDER/DB_PORT=$DB_PORT/g" "$backend_path/core/settings/.env"

    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Setting up PostgreSQL connection for application has failed. Exiting...${RESET}"
        exit 1
    fi
    echo -e "${GREEN}::: Connection has been set up.${RESET}"

    echo "::: Installing required packages and setting up the virtual environment..."
    # python3-devel postgresql-devel unixODBC-devel
    if [ "$OS" = "centos" ] && [ "$ONLINE_CONNECTION" = true ]; then
        packages=("libjpeg-turbo-devel" "zlib-devel" "python3-devel" "zlib-devel" "postgresql15-devel" "mariadb-devel" "libtool-ltdl" "unixODBC" "unixODBC-devel")
        total_packages=${#packages[@]}
        duration=${total_packages}
        #rpm -ivh https://www.rpmfind.net/linux/centos-stream/10-stream/AppStream/x86_64/os/Packages/perl-IPC-Cmd-1.04-512.el10.noarch.rpm
        dnf config-manager --set-enabled crb >/dev/null &
        dnf makecache 2>&1 >/dev/null
        dnf install $silent_output perl-IPC-Run >/dev/null
        ###testing-without###rpm -ivh https://www.rpmfind.net/linux/centos-stream/10-stream/CRB/x86_64/os/Packages/perl-IPC-Run-20231003.0-6.el10.noarch.rpm
        $PKG_MANAGER install $silent_output "${packages[@]}" >/dev/null &
        #$PKG_MANAGER install $silent_output -y libjpeg-turbo-devel zlib-devel
        #$PKG_MANAGER install $silent_output -y python3-devel postgresql15-devel mariadb-devel
        #$PKG_MANAGER install $silent_output -y libtool-ltdl unixODBC unixODBC-devel
        display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install dependencies packages for the backend installation. Exiting...${RESET}" "$duration"
        #rpm -ivh https://www.rpmfind.net/linux/centos-stream/10-stream/AppStream/x86_64/os/Packages/unixODBC-2.3.12-6.el10.x86_64.rpm
        #rpm -ivh https://www.rpmfind.net/linux/centos-stream/10-stream/CRB/x86_64/os/Packages/unixODBC-devel-2.3.12-6.el10.x86_64.rpm
        pip3 install --no-cache-dir --force-reinstall -r $CURRENT_PATH/requirements.txt >/dev/null 2>&1
        pip3 install urllib3 --no-cache-dir --ignore-installed >/dev/null 2>&1

    # python3-devel postgresql-devel unixODBC-devel
    # postgresql15-devel, MariaDB-devel,
    elif [ "$OS" = "centos" ] && [ "$ONLINE_CONNECTION" = false ]; then
        rpm_count=$(ls -1 "$RPM_PATH/$OS$major_version/postgres/$PG_VERSION/devel"/*.rpm 2>/dev/null | wc -l)
        if [ "$rpm_count" -gt 0 ]; then
            duration=$rpm_count
        else
            echo -e "${RED}ERROR: No RPM files found in $RPM_PATH/$OS$major_version/postgres/$PG_VERSION/devel/ directory. Exiting...${RESET}"
            exit 1
        fi
        $PKG_MANAGER localinstall $silent_output --nobest --disablerepo=* "$RPM_PATH/$OS$major_version/postgres/$PG_VERSION/devel"/*.rpm 2>&1 >/dev/null &
        display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install required packages. Exiting...${RESET}" "$duration"

        rpm_count=$(ls -1 "$RPM_PATH/$OS$major_version/mariadb/$MARIADB_VERSION/devel"/*.rpm 2>/dev/null | wc -l)
        if [ "$rpm_count" -gt 0 ]; then
            duration=$rpm_count
        else
            echo -e "${RED}ERROR: No RPM files found in $RPM_PATH/$OS$major_version/mariadb/$MARIADB_VERSION/devel/ directory. Exiting...${RESET}"
            exit 1
        fi
        $PKG_MANAGER localinstall $silent_output --nobest --disablerepo=* "$RPM_PATH/$OS$major_version/mariadb/$MARIADB_VERSION/devel"/*.rpm 2>&1 >/dev/null &
        display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install required packages. Exiting...${RESET}" "$duration"

        echo "export PATH=$PATH:/usr/pgsql-$PG_VERSION/bin" >> ~/.bashrc
        # TO CHECK:
        su - postgres -c 'echo "export PATH=$PATH:/usr/pgsql-$PG_VERSION/bin" >> ~/.bashrc'
        source ~/.bashrc
    elif [ "$OS" = "ubuntu" ]; then
            if [ "$ONLINE_CONNECTION" = true ]; then
            confirm_and_update_packages
            packages=("unixodbc" )
            if [ "$major_version" = 22 ]; then
                packages+=( "python3-dev" "python3-venv" )
            fi
                        total_packages=${#packages[@]}
                        duration=${total_packages}  # Duration for the progress bar
                        # Install all missing backend dependencies
                        $PKG_MANAGER install $silent_output "${packages[@]}" 2>&1 >/dev/null &
                        display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install pre-requisite packages for backend. Exiting...${RESET}" "$duration"
                else
                    deb_count=$(ls -1 "$RPM_PATH/$OS$major_version/postgres/$PG_VERSION/devel"/*.deb 2>/dev/null | wc -l)
            if [ "$deb_count" -gt 0 ]; then
                duration=$deb_count
            else
                echo -e "${RED}ERROR: No DEB files found in $RPM_PATH/$OS$major_version/postgres/$PG_VERSION/devel/ directory. Exiting...${RESET}"
                exit 1
            fi
            $PKG_MANAGER install $silent_output "$RPM_PATH/$OS$major_version/postgres/$PG_VERSION/devel"/*.deb 2>&1 >/dev/null &
            display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install required packages. Exiting...${RESET}" "$duration"
        fi

        deb_count=$(ls -1 "$RPM_PATH/$OS$major_version/mariadb/$MARIADB_VERSION/devel"/*.deb 2>/dev/null | wc -l)
        if [ "$deb_count" -gt 0 ]; then
            duration=$deb_count
        else
      pip3 show whitenoise
      echo -e "${RED}ERROR: No DEB files found in $RPM_PATH/$OS$major_version/mariadb/$MARIADB_VERSION/devel/ directory. Exiting...${RESET}"
            exit 1
        fi
        $PKG_MANAGER install $silent_output "$RPM_PATH/$OS$major_version/mariadb/$MARIADB_VERSION/devel"/*.deb 2>&1 >/dev/null &
        display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install required packages. Exiting...${RESET}" "$duration"
    else
        echo -e "${RED}ERROR: Unsupported distribution. Exiting...${RESET}"
        exit 1
    fi

    # Create and activate a virtual environment
    python3 -m venv "$backend_path/venv"
    source "$backend_path/venv/bin/activate"

    pip3 install --no-cache-dir --force-reinstall -r $backend_path/requirements.txt >/dev/null 2>&1

    # Check if the virtual environment is activated
    # -n flag checks if the VIRTUAL_ENV variable is non-empty
    if [ -n "$VIRTUAL_ENV" ]; then
        echo -e "${GREEN}::: Virtual environment is activated: $VIRTUAL_ENV${RESET}"
    else
        echo -e "${RED}::: Virtual environment is not activated.${RESET}"
        echo -e "${RED}ERROR: Could not continue with installation of Python packages using pip3. Exiting...${RESET}"
        exit 1
    fi

    # Install Python dependencies
    if [ "$ONLINE_CONNECTION" = false ]; then
        python3 -m pip install "$RPM_PATH"/python3/wheels/pip3/*.whl 2>&1 >/dev/null
        whl_count=$(ls -1 "$RPM_PATH"/python3/wheels/*.whl 2>/dev/null | wc -l)
            if [ "$whl_count" -gt 0 ]; then
                duration=$((whl_count))
            else
                echo -e "${RED}ERROR: No wheels files found in $RPM_PATH/python3/wheels directory. Exiting...${RESET}"
                deactivate
                exit 1
        fi
    fi
    #python3 -m pip install "$RPM_PATH"/python3/wheels/*.whl 2>&1 >/dev/null &
    #display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install Python packages using pip3. Exiting...${RESET}" "$duration" "true"
    #python3 -m pip install "$RPM_PATH"/python3/wheels/psycopg2* 2>&1 >/dev/null &
    #display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install Python packages using pip3. Exiting...${RESET}" "1" "true"
    #python3 -m pip install "$RPM_PATH"/python3/wheels/mariadb* 2>&1 >/dev/null &
    #display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install Python packages using pip3. Exiting...${RESET}" "1" "true"

        # Further are using development settings pattern, since before production some additional preparations must be done
    # Apply database migrations
    pip3 install django >/dev/null 2>&1
    pip3 install python-dotenv >/dev/null 2>&1

    python3 "$backend_path/manage.py" makemigrations 2>&1 >/dev/null &
    display_progress "$!" "spinner" "${RED}ERROR: Failed to make migrations. Exiting...${RESET}" "0" "true"

    python3 "$backend_path/manage.py" migrate 2>&1 >/dev/null &
    display_progress "$!" "spinner" "${RED}ERROR: Failed to migrate. Exiting...${RESET}" "0" "true"

    echo -e "${GREEN}::: Installation of required packages and setup of the virtual environment completed.${RESET}"
    echo "::: Creating a superuser for the application..."
    # Create a superuser (you will be prompted to enter details)
    python3 "$backend_path/manage.py" createsuperuser
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to create the superuser. Exiting...${RESET}"
        deactivate
        exit 1
    fi

    # echo -e "${GREEN}::: Server was started.${RESET}"
    deactivate
    echo -e "${GREEN}::: Virtual environment is deactivated.${RESET}"

    echo "::: Creating an organization object for the application..."

    su - postgres -c "psql -p $DB_PORT -d \"$APP_DB_NAME\" -c 'INSERT INTO public.organization (date_created, ind_disable_all_nodes, organization_name, ind_enable_notifications, ind_housekeeper, housekeeper_short_retention, housekeeper_long_retention, max_notifications_per_hour) VALUES (now(), '\''N'\'', '\''$ORG_NAME'\'', '\''Y'\'', '\''Y'\'', $housekeeper_short_retention, $housekeeper_long_retention, $max_notifications_per_hour);'"
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to create the organization object. Exiting...${RESET}"
        exit 1
    fi
    su - postgres -c "psql -p $DB_PORT -d \"$APP_DB_NAME\" -c 'INSERT INTO public.\"clusterCore_profile\" (org_id, user_id, is_demo) VALUES (1, 1, false);'"
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to create the organization object. Exiting...${RESET}"
        exit 1
    fi

    if [ "$private_key" = "true" ]; then
                ex_params='{\"myself\": true}'
                private_key_value="'$CREDENTIAL'"
                password_value="''"
        else
                ex_params='{\"myself\": true}'
                private_key_value="''"
                password_value="'$CREDENTIAL'"
        fi

        su - postgres -c "psql -p $DB_PORT -d \"$APP_DB_NAME\" -c \"INSERT INTO public.\\\"clusterCore_clusterapp_host\\\" (\\\"name\\\", ssh_port, username, \\\"password\\\", private_key, created_date, last_update_date, status, ind_deleted, ex_params, created_by_id, last_update_by_id) VALUES ('$hostname', '$SSH_PORT', 'root', $password_value, $private_key_value, now(), now(), 'ready', false, '$ex_params'::jsonb, 1, 1);\""
    if [ $? -ne 0 ]; then
        echo -e "${RED}ERROR: Failed to create the app host object. Exiting...${RESET}"
        exit 1
    fi

    su - postgres -c "psql -p $DB_PORT -d \"$APP_DB_NAME\" -f \"$DUMP_MONITOR_TASK_DEFINITIONS_TABLE_FILE\""
    if [ $? -ne 0 ]; then
        echo -e "${YELLOW}WARNING: Failed to insert task definitions into public.clusterCore_task table.${RESET}"
    fi

    rm -rf "$pg_home_dir/monitors"

    echo -e "${GREEN}::: Organization object was created.${RESET}"

    cd "$CURRENT_PATH"
}

install_frontend_folder() {
    frontend_path="$CURRENT_PATH/frontend"

    echo "::: Installing nodejs package..."

    # Edit the API URL in the index.js file
    # vi $frontend_path/src/app/config/index.js

    # centos 7, ubuntu 18: wget https://nodejs.org/dist/latest-v16.x/node-v16.20.2-linux-x64.tar.xz
    # centos 8, ubuntu 20: wget https://nodejs.org/dist/v18.18.0/node-v18.18.0-linux-x64.tar.xz
    if [ "$ONLINE_CONNECTION" = false ]; then
        if { [ "$OS" = "centos" ] && [ "$major_version" = "7" ]; } || { [ "$OS" = "ubuntu" ] && [ "$major_version" = "18" ]; }; then
                tar -C /usr/local -xvf "$$RPM_PATH"/node-v16.20.2*.tar.xz 2>&1 >/dev/null &
                display_progress "$!" "spinner" "${RED}ERROR: Failed to untar nodejs file. Exiting...${RESET}"

                ln -s /usr/local/node-v16.20.2-linux-x64/bin/node /usr/local/bin/
                ln -s /usr/local/node-v16.20.2-linux-x64/bin/npm /usr/local/bin/
        elif { [ "$OS" = "centos" ] && { [ "$major_version" = "8" ] || [ "$major_version" = "9" ]; }; } || { [ "$OS" = "ubuntu" ] && { [ "$major_version" = "20" ] || [ "$major_version" = "22" ]; }; }; then
                tar -C /usr/local -xvf "$RPM_PATH"/nodejs/node-v18.18.0*.tar.xz 2>&1 >/dev/null &
                display_progress "$!" "spinner" "${RED}ERROR: Failed to untar nodejs file. Exiting...${RESET}"

                ln -s /usr/local/node-v18.18.0-linux-x64/bin/node /usr/local/bin/
                ln -s /usr/local/node-v18.18.0-linux-x64/bin/npm /usr/local/bin/
        fi
    fi


    if [ "$ONLINE_CONNECTION" = true ]; then
        curl -sL https://rpm.nodesource.com/setup_18.x | sudo bash -
        if $PKG_MANAGER $silent_output install nodejs >/dev/null 2>&1; then
            echo -e "${GREEN}::: nodejs package was installed.${RESET}"
        else
            echo "Node.js installation failed."
        fi
    fi

    cd "$frontend_path"
    # echo "::: Installing frontend dependencies..."
    echo "::: Untar 'node_modules' directory..."

    # To pack packages: npm pack
    # npm install "$RPM_PATH"/nodejs/clusterapp*.tgz 2>&1 >/dev/null &
    # display_progress "$!" "spinner" "${RED}ERROR: Frontend dependencies were not installed. Exiting...${RESET}"

    # will extract node_modules folder to current folder, no matter how deep the paths in tar.gz archive
    tar -C "$frontend_path" --transform='s|.*/node_modules|node_modules|' -xzf "$frontend_path"/node_modules.tar.gz 2>&1 >/dev/null & 2>&1 >/dev/null &
    display_progress "$!" "spinner" "${RED}ERROR: Could not untar node_modules directory. Exiting...${RESET}"

    echo -e "${GREEN}::: The 'node_modules' directory has been untarred.${RESET}"

    # Start the frontend application
    # echo "::: Starting the frontend application..."
    # nohup npm start >/dev/null 2>&1 &
    # if [ $? -ne 0 ]; then
    #     echo -e "${RED}ERROR: Failed to start frontend application. Exiting...${RESET}"
    #     exit 1
    # fi

    # echo -e "${GREEN}::: Frontend application was started.${RESET}"
}

install_tasks_folder() {
    cd "$tasks_path"
    # pip3 config set global.disable-pip-version-check true
    # Ensure sysstat is installed on all relevant machines
    # vi ./task_core.py  - put data in get_postgres_connection()
    # return psycopg2.connect(database = 'DB_PLACEHOLDER', user = 'USER_PLACEHOLDER', password = 'PWD_PLACEHOLDER', host = 'HOST_PLACEHOLDER', port = 'PORT_PLACEHOLDER')

    # Check if DB_USERNAME is empty
    if [ -z "$DB_USERNAME" ]; then
        echo -e "${RED}ERROR: No username detected for $APP_DB_NAME database. Exiting...${RESET}"
        exit 1
    fi

    # Check if PWD_USERNAME is empty
    if [ -z "$PWD_USERNAME" ]; then
        echo -e "${RED}ERROR: No password detected for $APP_DB_NAME database. Exiting...${RESET}"
        exit 1
    fi


    sed -i "s#PATH_PLACEHOLDER#$tasks_path#" $tasks_path/task_service.py
    cp "$tasks_path/.env_placeholders" "$tasks_path/.env"
    sed -i "s/DB_NAME=DB_PLACEHOLDER/DB_NAME=$APP_DB_NAME/g" "$tasks_path/.env"
    sed -i "s/DB_USER=USER_PLACEHOLDER/DB_USER=$DB_USERNAME/g" "$tasks_path/.env"
    sed -i "s/DB_PASSWORD=PWD_PLACEHOLDER/DB_PASSWORD=$PWD_USERNAME/g" "$tasks_path/.env"
    sed -i "s/DB_HOST=HOST_PLACEHOLDER/DB_HOST=$ip_address/g" "$tasks_path/.env"
    sed -i "s/DB_PORT=PORT_PLACEHOLDER/DB_PORT:$DB_PORT/g" "$tasks_path/.env"

    chmod +x task_service.py

    # Path to the SQL file containing your functions
    SQL_FILE="$CURRENT_PATH/scripts/clusterapp_functions.sql"

    # Execute the SQL file using psql
    su - postgres -c "PGPASSWORD=$PWD_USERNAME psql -p $DB_PORT -h $ip_address -p $DB_PORT -U $DB_USERNAME -d $APP_DB_NAME" < $SQL_FILE 2>&1 >/dev/null &
    display_progress "$!" "spinner" "${RED}ERROR: Failed to create PostgreSQL functions. Exiting...${RESET}"

    python3 -m venv "$tasks_path/venv"
    source "$tasks_path/venv/bin/activate"

    # Check if the virtual environment is activated
    # -n flag checks if the VIRTUAL_ENV variable is non-empty
    if [ -n "$VIRTUAL_ENV" ]; then
        echo -e "${GREEN}::: Virtual environment is activated: $VIRTUAL_ENV${RESET}"
    else
        echo "::: Virtual environment is not activated"
        echo -e "${RED}ERROR: Could not continue with installation of Python packages using pip3. Exiting...${RESET}"
        exit 1
    fi

    if [ "$OS" = "centos" ]; then
        export PATH=/usr/pgsql-$PG_VERSION/bin/:$PATH
    fi

    echo "::: Installing tasks dependencies..."
    # Install Python dependencies
    if [ "$ONLINE_CONNECTION" = true ]; then
        python3 -m pip install --upgrade pip 2>&1 >/dev/null &
        display_progress "$!" "spinner" "${RED}ERROR: Failed to upgrade pip3. Exiting...${RESET}" "0" "true"
        python3 -m pip install -r "$tasks_path/tasks_requirements.txt" 2>&1 >/dev/null &
        display_progress "$!" "spinner" "${RED}ERROR: Failed to install Python packages using pip3. Exiting...${RESET}" "0" "true"
    else
        python3 -m pip install "$RPM_PATH"/python3/wheels/pip3/*.whl 2>&1 >/dev/null
        whl_count=$(ls -1 "$RPM_PATH"/python3/wheels/*.whl 2>/dev/null | wc -l)
        if [ "$whl_count" -gt 0 ]; then
            duration=$((whl_count))
        else
            echo -e "${RED}ERROR: No wheels files found in $RPM_PATH/python3/wheels/ directory. Exiting...${RESET}"
            deactivate
            exit 1
        fi
        python3 -m pip install "$RPM_PATH"/python3/wheels/*.whl 2>&1 >/dev/null &
        display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install Python packages using pip3. Exiting...${RESET}" "$duration" "true"
        python3 -m pip install "$RPM_PATH"/python3/wheels/psycopg2* 2>&1 >/dev/null &
        display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install Python packages using pip3. Exiting...${RESET}" "1" "true"
    fi
    echo -e "${GREEN}::: Tasks dependencies were installed.${RESET}"

    # echo "::: Starting the tasks..."
    # nohup "$tasks_path/task_service.py" >/dev/null 2>&1 &

    # pid=$!
    # if [ $? -ne 0 ]; then
    #     echo -e "${RED}ERROR: Failed to start the tasks. Exiting...${RESET}"
    #     kill -9 $pid
    #     deactivate
    #     exit 1
    # fi

    # echo -e "${GREEN}::: Tasks were started.${RESET}"
    deactivate
    echo -e "${GREEN}::: Virtual environment is deactivated.${RESET}"
}

function handle_certificate_options() {
    while true; do
        echo "Please choose one of the following options:"
        echo "1. Provide certificate and key."
        echo "2. Create a self-signed certificate."
        #echo "3. No certificate."
        read -p "Enter the option number (1/2): " choice
        case $choice in
            1)
                echo "You chose to provide a certificate and key."
                read -p "Enter the path to the certificate file: " cert_file
                read -p "Enter the path to the key file: " key_file

                # Check if the provided files exist
                if [ -f "$cert_file" ] && [ -f "$key_file" ]; then
                    echo "Certificate file: $cert_file"
                    echo "Key file: $key_file"
                else
                    echo -e "${RED}ERROR: Certificate file or key file not found.${RESET}"
                    continue
                fi
                ;;
            2)
                certificate_registering=true
                while [ "$certificate_registering" = true ]; do
                    read -p "Enter the domain for the self-signed certificate: " domain
                    echo "You entered the domain: $domain"

                    read -p "Is this correct? (y/c to change): " confirm

                    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
                        echo "Generating self-signed certificate for $domain..."

                        ssl_config="$backend_path/clusterapp.cnf"
                        cert_file="$backend_path/clusterapp.crt"
                        sign_request_file="$backend_path/clusterapp.csr"
                        key_file="$backend_path/clusterapp.key"

                        template="[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = State
L = City
O = ClusterApp
OU = ClusterApp
CN = $domain

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = $domain"
                        echo "$template" > "$ssl_config"
                        openssl req -new -sha256 -nodes -out $sign_request_file -newkey rsa:2048 -keyout $key_file -config $ssl_config
                        openssl x509 -req -in $sign_request_file -signkey $key_file -out $cert_file -days 365 -extfile $ssl_config -extensions req_ext
                        echo "Certificate file: $cert_file"
                        echo "Key file: $key_file"
                        certificate_registering=false
                    elif [ "$confirm" = "c" ] || [ "$confirm" = "C" ]; then
                        continue  # Allow the user to enter the domain again
                    else
                        echo "Invalid option. Please enter 'y' or 'c' only."
                    fi
                done
                ;;
            # 3)
            #     echo "You chose not to use a certificate."
            #     cert_file=""  # No certificate file
            #     key_file=""   # No key file
            #     ;;
            *)
                echo "Invalid option. Please enter 1, 2, or 3."
                continue
                ;;
        esac

        service_path="/etc/systemd/system"
        #if [ -f "$service_path/clusterapp.target" ]; then
        #    echo -e "${RED}ERROR: Service clusterapp already exist. Exiting...${RESET}"
        #    exit 1
        #fi

        ENV_FILE="$backend_path/.env"

        # Check and install nginx
        echo "::: Installing nginx package..."

        if [ "$ONLINE_CONNECTION" = true ]; then
            if [ "$OS" = "centos" ]; then
                $PKG_MANAGER --enablerepo=appstream install $silent_output "nginx" 2>&1 >/dev/null &
                display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install nginx package. Exiting...${RESET}" "1"
            elif [ "$OS" = "ubuntu" ]; then
                $PKG_MANAGER install $silent_output "nginx" 2>&1 >/dev/null &
                display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install nginx package. Exiting...${RESET}" "1"
            fi
        else
            if [ "$OS" = "centos" ]; then
                $PKG_MANAGER localinstall $silent_output --nobest --disablerepo=* "$RPM_PATH/$OS$major_version"/nginx/*.rpm 2>&1 >/dev/null &
                display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install nginx package. Exiting...${RESET}" "1"
            elif [ "$OS" = "ubuntu" ]; then
                $PKG_MANAGER install $silent_output "$RPM_PATH/$OS$major_version"/nginx/*.deb 2>&1 >/dev/null &
                display_progress "$!" "progress_bar" "${RED}ERROR: Failed to install nginx package. Exiting...${RESET}" "1"
            fi
        fi

        echo -e "${GREEN}::: nginx package has been installed.${RESET}"

        template='server {
            listen 80;
            server_name __DOMAIN__;

            location / {
                return 301 https://$host$request_uri;
            }
        }

        server {
            listen 443 ssl;
            server_name __DOMAIN__;

            ssl_certificate __CERT_FILE__;
            ssl_certificate_key __KEY_FILE__;

            location / {
                proxy_pass https://127.0.0.1:__BACK_PORT__;
                proxy_ssl_verify off;
                                proxy_set_header Host $host;
                                proxy_set_header X-Real-IP $remote_addr;
                                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                                proxy_set_header X-Forwarded-Proto https;
                                proxy_connect_timeout 120s;
                                proxy_send_timeout 120s;
                                proxy_read_timeout 120s;
                                proxy_buffering off;

            }

                        keepalive_timeout 65;
                        sendfile on;
                        tcp_nopush on;
                        tcp_nodelay on;
        }'

        template="${template//__DOMAIN__/$domain}"
        template="${template//__CERT_FILE__/$cert_file}"
        template="${template//__KEY_FILE__/$key_file}"
        template="${template//__BACK_PORT__/$BACK_PORT}"

        echo "$template" > "/etc/nginx/conf.d/clusterapp.conf"
                systemctl restart nginx

        template="[Unit]
Description=ClusterApp services
Requires=gunicorn.service task_service.service
After=network.target

[Install]
WantedBy=multi-user.target"

        echo "$template" > "$service_path/clusterapp.target"

        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))")
        # echo "Generated SECRET_KEY: $SECRET_KEY"
        echo "::: Exporting environment variables..."
        export SECRET_KEY="$SECRET_KEY"
        export DJANGO_SETTINGS_MODULE='core.settings.production'
        export DATABASE_URL='your_database_url'
        echo '::: Saving environment variables to .env file...'
        echo "SECRET_KEY=$SECRET_KEY
        DJANGO_SETTINGS_MODULE=core.settings.production
        DATABASE_URL=your_database_url" >> .env

        template="[Unit]
Description=ClusterApp task service
After=network.target
PartOf=clusterapp.target

[Service]
Type=simple
WorkingDirectory=$tasks_path
Environment=\"PATH=$tasks_path/venv/bin/\"
ExecStart=$tasks_path/venv/bin/python3 $tasks_path/task_service.py
TimeoutStartSec=120
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target"
        echo "$template" > "$service_path/task_service.service"

        template="[Unit]
Description=gunicorn daemon
After=network.target
PartOf=clusterapp.target

[Service]
Type=simple
WorkingDirectory=$backend_path/
Environment=\"PATH=$backend_path/venv/bin/\"
Environment=\"PORT=$BACK_PORT\"
ExecStart=$backend_path/venv/bin/gunicorn -c gunicorn.py core.wsgi:application
TimeoutStartSec=120
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target"
        echo "$template" > "$service_path/gunicorn.service"

        systemctl daemon-reload
        systemctl enable "clusterapp.target"
        systemctl start "clusterapp.target" &
        display_progress "$!" "spinner" "${RED}ERROR: Failed to start clusterapp.target. Exiting...${RESET}" "1"
        break
    done
}
function install_azurite() {
    echo "::: Installing azurite package..."

    npm install -g n &
    display_progress "$!" "spinner" "${RED}ERROR: azurite package was not installed. Exiting...${RESET}" "1"

    npm install -g azurite &
    display_progress "$!" "spinner" "${RED}ERROR: azurite package was not installed. Exiting...${RESET}" "1"

    template="[Unit]
Description=Azurite Blob Storage Emulator
After=network.target

[Service]
ExecStart=/usr/local/node-v18.18.0-linux-x64/bin/azurite-blob --blobHost=0.0.0.0 --location=/backups/ --silent
WorkingDirectory=/usr/local/node-v18.18.0-linux-x64/bin
Restart=always
RestartSec=3
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=azurite

[Install]
WantedBy=multi-user.target"
    echo "$template" > "$service_path/azurite.service"
    systemctl daemon-reload
    systemctl enable azurite
    systemctl start azurite &
    display_progress "$!" "spinner" "${RED}ERROR: Failed to start azurite.service. Exiting...${RESET}" "1"

    echo -e "${GREEN}::: azurite package was installed.${RESET}"
}

######## SCRIPT ############
verifyFreeDiskSpace

distributionDetector

#check_online_connection

install_required_packages
# Get the IP address of the default network interface (net-tools)
# HOST_IP=$(ifconfig | grep -A1 '^[[:alnum:]]' | awk '/inet / {print $2}' | head -n 1)
HOST_IP="0.0.0.0"

ports=("DB_PORT" "BACK_PORT" "FRONT_PORT")

for port in "${ports[@]}"; do
    check_port_in_use "${!port}"  # Use ${!port} to get the value of the variable
done

install_python310

install_postgresql

while true; do
    read -p '::: Would you like to install the Oracle driver? (y/n): ' install_oracle_driver_var
    if [ "$install_oracle_driver_var" = 'y' ] || [ "$install_oracle_driver_var" = 'Y' ]; then
        install_oracle_driver
        break
    elif [ "$install_oracle_driver_var" = 'n' ] || [ "$install_oracle_driver_var" = 'N' ]; then
        echo '::: Oracle driver installation skipped.'
        break
    else
        echo 'Please enter 'y' or 'n' only.'
    fi
done

install_backend_folder

install_frontend_folder

install_tasks_folder

handle_certificate_options

install_azurite

echo "::: ClusterApp Application is now running and can be accessed at https://$ip_address"
echo -e "${BLUE}::: -------------------------------------------------------- :::${RESET}"
echo -e "${BLUE}::: ClusterApp Application Setup and Configuration Completed :::${RESET}"
