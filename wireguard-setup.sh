#!/bin/bash

# WireGuard VPS Setup Script
# Automated installation and configuration for Ubuntu VPS
# Compatible with Oracle Cloud and other cloud providers

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
WG_CONFIG_DIR="/etc/wireguard"
WG_INTERFACE="wg0"
SERVER_WG_IP="10.8.0.1/24"
SERVER_PORT="51820"
CLIENT_DNS="1.1.1.1, 8.8.8.8"

# Helper functions
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
        exit 1
    fi
}

# Check if user has sudo privileges
check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        print_error "This script requires sudo privileges. Please ensure your user can run sudo commands."
        exit 1
    fi
}

# Detect network interface
detect_interface() {
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [[ -z "$INTERFACE" ]]; then
        print_error "Could not detect network interface"
        exit 1
    fi
    print_status "Detected network interface: $INTERFACE"
}

# Get server public IP
get_public_ip() {
    PUBLIC_IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || curl -s icanhazip.com)
    if [[ -z "$PUBLIC_IP" ]]; then
        print_warning "Could not automatically detect public IP"
        read -p "Please enter your server's public IP address: " PUBLIC_IP
    fi
    print_status "Server public IP: $PUBLIC_IP"
}

# Update system
update_system() {
    print_status "Updating system packages..."
    sudo apt update && sudo apt upgrade -y
    print_success "System updated successfully"
}

# Install WireGuard
install_wireguard() {
    print_status "Installing WireGuard..."
    sudo apt install wireguard qrencode -y
    print_success "WireGuard installed successfully"
}

# Install UFW if not present
install_ufw() {
    if ! command -v ufw &> /dev/null; then
        print_status "Installing UFW firewall..."
        sudo apt install ufw -y
    fi
}

# Generate server keys
generate_server_keys() {
    print_status "Generating server keys..."
    cd $WG_CONFIG_DIR
    sudo wg genkey | sudo tee server_private.key > /dev/null
    sudo cat server_private.key | wg pubkey | sudo tee server_public.key > /dev/null
    sudo chmod 600 server_private.key
    print_success "Server keys generated"
}

# Create server configuration
create_server_config() {
    print_status "Creating server configuration..."
    
    SERVER_PRIVATE_KEY=$(sudo cat $WG_CONFIG_DIR/server_private.key)
    
    sudo tee $WG_CONFIG_DIR/$WG_INTERFACE.conf > /dev/null <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $SERVER_WG_IP
ListenPort = $SERVER_PORT
SaveConfig = true

# Enable IP forwarding and NAT
PostUp = echo 1 > /proc/sys/net/ipv4/ip_forward
PostUp = iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE

PostDown = iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE
EOF

    sudo chmod 600 $WG_CONFIG_DIR/$WG_INTERFACE.conf
    print_success "Server configuration created"
}

# Enable IP forwarding permanently
enable_ip_forwarding() {
    print_status "Enabling IP forwarding..."
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sysctl -p > /dev/null
    print_success "IP forwarding enabled"
}

# Configure firewall
configure_firewall() {
    print_status "Configuring firewall..."
    
    # Allow SSH (important!)
    sudo ufw allow 22/tcp > /dev/null
    
    # Allow WireGuard port
    sudo ufw allow $SERVER_PORT/udp > /dev/null
    
    # Enable UFW
    sudo ufw --force enable > /dev/null
    
    print_success "Firewall configured"
    print_status "UFW rules:"
    sudo ufw status
}

# Start WireGuard service
start_wireguard() {
    print_status "Starting WireGuard service..."
    
    sudo systemctl enable wg-quick@$WG_INTERFACE
    sudo systemctl start wg-quick@$WG_INTERFACE
    
    # Check if service started successfully
    if sudo systemctl is-active --quiet wg-quick@$WG_INTERFACE; then
        print_success "WireGuard service started successfully"
    else
        print_error "Failed to start WireGuard service"
        sudo systemctl status wg-quick@$WG_INTERFACE
        exit 1
    fi
}

# Generate client configuration
generate_client_config() {
    local client_name=$1
    local client_ip=$2
    
    print_status "Generating client configuration for: $client_name"
    
    # Generate client keys
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo $CLIENT_PRIVATE_KEY | wg pubkey)
    
    # Get server public key
    SERVER_PUBLIC_KEY=$(sudo cat $WG_CONFIG_DIR/server_public.key)
    
    # Add peer to server
    sudo wg set $WG_INTERFACE peer $CLIENT_PUBLIC_KEY allowed-ips $client_ip/32
    sudo wg-quick save $WG_INTERFACE
    
    # Create client config file
    CLIENT_CONFIG="$client_name.conf"
    
    cat > $CLIENT_CONFIG <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $client_ip/32
DNS = $CLIENT_DNS

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $PUBLIC_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    print_success "Client configuration created: $CLIENT_CONFIG"
    
    # Generate QR code
    print_status "Generating QR code for mobile devices..."
    qrencode -t ansiutf8 < $CLIENT_CONFIG
    echo ""
    
    return 0
}

# Main installation function
main_install() {
    print_status "Starting WireGuard VPS installation..."
    echo "=================================="
    
    check_root
    check_sudo
    detect_interface
    get_public_ip
    
    update_system
    install_wireguard
    install_ufw
    
    # Create WireGuard directory if it doesn't exist
    sudo mkdir -p $WG_CONFIG_DIR
    
    generate_server_keys
    create_server_config
    enable_ip_forwarding
    configure_firewall
    start_wireguard
    
    print_success "WireGuard server installation completed!"
    
    # Show server status
    echo ""
    print_status "Server Status:"
    sudo wg show
    
    echo ""
    print_status "Server Configuration:"
    echo "- WireGuard IP: $SERVER_WG_IP"
    echo "- Listen Port: $SERVER_PORT"
    echo "- Public IP: $PUBLIC_IP"
    echo "- Interface: $INTERFACE"
}

# Client management function
manage_clients() {
    while true; do
        echo ""
        echo "=================================="
        echo "Client Management"
        echo "=================================="
        echo "1. Add new client"
        echo "2. List existing clients"
        echo "3. Remove client"
        echo "4. Show server status"
        echo "5. Exit"
        echo ""
        read -p "Choose an option (1-5): " choice
        
        case $choice in
            1)
                read -p "Enter client name: " client_name
                read -p "Enter client IP (e.g., 10.8.0.2): " client_ip
                
                # Validate IP format
                if [[ ! $client_ip =~ ^10\.8\.0\.[0-9]+$ ]]; then
                    print_error "Invalid IP format. Use 10.8.0.x format"
                    continue
                fi
                
                generate_client_config "$client_name" "$client_ip"
                ;;
            2)
                print_status "Current clients:"
                sudo wg show
                ;;
            3)
                read -p "Enter client public key to remove: " client_pubkey
                sudo wg set $WG_INTERFACE peer $client_pubkey remove
                sudo wg-quick save $WG_INTERFACE
                print_success "Client removed"
                ;;
            4)
                sudo wg show
                ;;
            5)
                break
                ;;
            *)
                print_error "Invalid option"
                ;;
        esac
    done
}

# Check if WireGuard is already installed
check_existing_installation() {
    if sudo systemctl is-active --quiet wg-quick@$WG_INTERFACE 2>/dev/null; then
        print_warning "WireGuard appears to be already installed and running"
        echo ""
        echo "Options:"
        echo "1. Manage existing installation (add/remove clients)"
        echo "2. Reinstall from scratch (WARNING: This will remove existing configuration)"
        echo "3. Exit"
        echo ""
        read -p "Choose an option (1-3): " choice
        
        case $choice in
            1)
                get_public_ip
                manage_clients
                exit 0
                ;;
            2)
                print_warning "Removing existing WireGuard installation..."
                sudo systemctl stop wg-quick@$WG_INTERFACE 2>/dev/null || true
                sudo systemctl disable wg-quick@$WG_INTERFACE 2>/dev/null || true
                sudo rm -rf $WG_CONFIG_DIR/$WG_INTERFACE.conf
                print_status "Existing installation removed. Proceeding with fresh installation..."
                ;;
            3)
                exit 0
                ;;
            *)
                print_error "Invalid option"
                exit 1
                ;;
        esac
    fi
}

# Display important notes
show_notes() {
    echo ""
    print_success "Installation completed successfully!"
    echo ""
    print_warning "IMPORTANT NOTES:"
    echo "=================================="
    echo "1. If using Oracle Cloud, make sure to add these security rules:"
    echo "   - Ingress Rule: UDP port $SERVER_PORT from 0.0.0.0/0"
    echo ""
    echo "2. Client configuration files have been created in the current directory"
    echo "   - Import these files into your WireGuard client applications"
    echo ""
    echo "3. For mobile devices, use the QR codes displayed above"
    echo ""
    echo "4. Default client IP range: 10.8.0.x"
    echo "   - Server: 10.8.0.1"
    echo "   - Clients: 10.8.0.2, 10.8.0.3, etc."
    echo ""
    echo "5. To manage clients later, run this script again"
    echo ""
    print_status "Server is ready and listening on $PUBLIC_IP:$SERVER_PORT"
}

# Main script execution
main() {
    echo "=================================="
    echo "WireGuard VPS Setup Script"
    echo "=================================="
    echo "This script will install and configure WireGuard on your VPS"
    echo ""
    
    check_existing_installation
    main_install
    
    # Ask if user wants to create client configurations
    echo ""
    read -p "Do you want to create client configurations now? (y/n): " create_clients
    
    if [[ $create_clients =~ ^[Yy]$ ]]; then
        manage_clients
    fi
    
    show_notes
}

# Run main function
main "$@"
