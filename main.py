import sys
from config import ConfigManager
from server import CCcamServer


def print_banner(config, users, readers):
    """Print startup banner"""
    print("\n" + "=" * 70)
    print("        CCcam Server - Professional Card Sharing")
    print(f"             Version {config.version} Build {config.build}")
    print("=" * 70)
    print(f"\nServer Configuration:")
    print(f"  Listen:         {config.host}:{config.port}")
    print(f"  Max Clients:    {config.max_clients}")
    print(f"  ECM Folder:     {config.ecm_folder}")
    print(f"  Log Level:      {config.log_level}")
    
    print(f"\nReaders: {len(readers)}")
    print("-" * 70)
    print(f"{'Label':<15} {'Protocol':<12} {'Group':<8} {'CAIDs':<30}")
    print("-" * 70)
    for reader in readers:
        if reader.caid_list:
            caids = ",".join([f"{c:04X}" for c in reader.caid_list[:5]])
            if len(reader.caid_list) > 5:
                caids += f" +{len(reader.caid_list)-5}"
        else:
            caids = "ALL"
        print(f"{reader.label:<15} {reader.protocol:<12} {reader.group:<8} {caids:<30}")
    
    print(f"\nUser Accounts: {len(users)}")
    print("-" * 70)
    print(f"{'Username':<15} {'Status':<10} {'Group':<8} {'CAIDs':<25} {'Max Conn':<10}")
    print("-" * 70)
    
    for user in users:
        status = "ENABLED" if user.enabled else "DISABLED"
        if user.caid_list:
            caids = ",".join([f"{c:04X}" for c in user.caid_list[:4]])
            if len(user.caid_list) > 4:
                caids += f" +{len(user.caid_list)-4}"
        else:
            caids = "ALL"
        max_conn = "UNLIMITED" if user.max_connections == 0 else str(user.max_connections)
        print(f"{user.username:<15} {status:<10} {user.group:<8} {caids:<25} {max_conn:<10}")
    
    print("-" * 70)
    print()


def main():
    """Main entry point"""
    print("\nCCcam Server Starting...")
    
    config_file = "cccam.cfg"
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    
    try:
        config_manager = ConfigManager(config_file)
        config, users, readers = config_manager.load()
        
        print_banner(config, users, readers)
        
        if not users:
            print("ERROR: No users configured. Please edit cccam.cfg")
            sys.exit(1)
        
        server = CCcamServer(config, users, readers)
        server.start()
    
    except KeyboardInterrupt:
        print("\n\nShutdown complete")
    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
