# runnable with nix build '.#nixos-integration-test' -L

{ pkgs, toy-dns-server }:

{
  name = "toy-dns-server-integration-test";

  nodes = {
    ### DNS server VM ###
    server = _: {
      # Write the example zone config
      environment.etc."dns/example_zone.yaml".text = ''
        example.com:
          records:
          - {name: "", type: AAAA, address: 2600:1406:5e00:6::17ce:bc1b}
          - {name: "", type: AAAA, address: 2600:1406:bc00:53::b81e:94c8}
      '';

      # Create a systemd service for the DNS server
      systemd.services.toy-dns-server = {
        description = "Toy DNS Server";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];

        serviceConfig = {
          ExecStart =
            "${toy-dns-server}/bin/toy-dns-server " +
            "--listen [::]:53 " +
            "--config /etc/dns/example_zone.yaml";
          Restart = "on-failure";
          # DNS servers typically need CAP_NET_BIND_SERVICE to bind to port 53
          AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
          DynamicUser = true;
        };
      };

      # Open DNS port in firewall
      networking.firewall.allowedUDPPorts = [ 53 ];
      networking.firewall.allowedTCPPorts = [ 53 ];
    };

    ### DNS client VM ###
    client = { pkgs, ... }: {
      environment.systemPackages = with pkgs; [ dnsutils ]; # provides dig
    };
  };

  ### Test script ###
  testScript = ''
    # Start all machines
    start_all()

    server.wait_for_unit("toy-dns-server.service")
    server.wait_for_open_port(53)

    server.succeed("journalctl -u toy-dns-server.service --no-pager "
                   "| grep -q 'Toy DNS server'")

    client.wait_for_unit("multi-user.target")

    print("Testing AAAA record query for example.com...")
    result = client.succeed("dig @server example.com AAAA +short")
    print(f"AAAA records: {result}")
    assert "2600:1406:5e00:6::17ce:bc1b" in result
    assert "2600:1406:bc00:53::b81e:94c8" in result

    print("Checking server logs...")
    print("All tests passed!")
  '';
}
