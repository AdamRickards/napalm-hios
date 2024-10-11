# Ideas to implement

## Safe configuration saving in HiOS environment
- A safe config update method to handle the fact HiOS doesnt have candidate merging and we run the risk when messing with config to save other peoples unsaved changes, or save a config change someone else made while we are working on the device.
- This method should check the running-config is in sync with NVM, grab the running config, execute the requested changes, check the updated running-config doesnt contain lines that we didnt set, and then write running-config to nvm.
- This simulates what other vendors in the I.T./enterprise space do with Candidate configurations, or configuration locking, to handle race conditions and multi-user environments.

    def safe_config_change(self, config_command):
        """
        Safely apply a configuration change to a HiOS device.
        
        :param config_command: The configuration command to apply
        :return: Dict with status of the operation and any relevant messages
        """
        # Check initial sync status
        if not self._is_config_in_sync():
            return {"status": "failed", "message": "Initial configuration not in sync with NVM"}
        
        # Take a snapshot of the relevant configuration section
        initial_config = self._get_relevant_config(config_command)
        
        # Apply the configuration change
        result = self.device.send_config_set([config_command])
        
        # Re-check sync status
        if not self._is_config_in_sync():
            # Configuration changed by another process during our operation
            self.device.send_config_set(["exit"])  # Exit config mode without saving
            return {"status": "failed", "message": "Configuration changed by another process"}
        
        # Verify the change
        new_config = self._get_relevant_config(config_command)
        if not self._verify_change(initial_config, new_config, config_command):
            self.device.send_config_set(["exit"])  # Exit config mode without saving
            return {"status": "failed", "message": "Unexpected configuration change"}
        
        # Save the configuration
        save_result = self.device.send_command("copy running-config nvm")
        
        return {"status": "success", "message": "Configuration changed and saved successfully"}

    def _is_config_in_sync(self):
        # Implementation to check if running config is in sync with NVM
        pass

    def _get_relevant_config(self, config_command):
        # Implementation to get the relevant section of the configuration
        pass

    def _verify_change(self, initial_config, new_config, expected_change):
        # Implementation to verify that only the expected change occurred
        pass

## HiDiscovery (including control such as disable or read-only)

- The ability to check HiDiscovery status as for Cybersecurity concious customers we might want to think about whether this is on, read-only or off in our production environments.
- The ability to change the state supporting on, off, read-only by passing the optional argument status=[on|off|ro]

# Media Redundancy Protocol

- The ability to check the status of Media Redundancy Protocol instance on the switch
- Returns the important information such as
- Operation [true|false],
- Ring port #1 [intf], Status [forwarding|blocking|not-connected]
- Ring port #2 [intf], Status [forwarding|blocking|not-connected], Fixed-backup [true|false]
- VLAN ID [0|int],
- Ring Manager enabled [true|false],
- Recovery Timer [200ms|500ms]
- Advanced Mode [true|false]
- Redundancy Status: [string] `for this value I think i'll use my own interpretation, if Ring Manager = False then we will return a string such as "Both ring ports operational" instead of "Redundancy Guarunteed" or similar device remark`
