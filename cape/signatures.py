# These heuristic maps are based on the first category listed for a signature in CAPE, and may be arbitrary
CAPE_SIGNATURES = {
    "accesses_mailslot": "Discovery",
    "accesses_netlogon_regkey": "Discovery",
    "accesses_primary_patition": "Bootkit",
    "accesses_recyclebin": "Evasion",
    "accesses_sysvol": "Credential Access",
    "adds_admin_user": "Account",
    "adds_user": "Account",
    "allaple_mutexes": "Malware",
    "alphacrypt_behavior": "Ransomware",
    "alters_windows_utility": "Command",
    "andromeda_behavior": "Trojan",
    "andromut_mutexes": "Trojan",
    "angler_js": "Exploit Kit",
    "anomalous_deletefile": "Malware",
    "antianalysis_detectfile": "Anti-analysis",
    "antianalysis_detectreg": "Anti-analysis",
    "antiav_360_libs": "Anti-av",
    "antiav_ahnlab_libs": "Anti-av",
    "antiav_apioverride_libs": "Anti-debug",
    "antiav_avast_libs": "Anti-av",
    "antiav_bitdefender_libs": "Anti-av",
    "antiav_bullgaurd_libs": "Anti-av",
    "antiav_detectfile": "Anti-av",
    "antiav_detectreg": "Anti-av",
    "antiav_emsisoft_libs": "Anti-av",
    "antiav_nthookengine_libs": "Anti-debug",
    "antiav_qurb_libs": "Anti-av",
    "antiav_servicestop": "Anti-av",
    "antiav_srp": "Anti-av",
    "antiav_whitespace": "Anti-av",
    "antidebug_addvectoredexceptionhandler": "Anti-debug",
    "antidebug_checkremotedebuggerpresent": "Anti-debug",
    "antidebug_debugactiveprocess": "Anti-debug",
    "antidebug_devices": "Anti-debug",
    "antidebug_gettickcount": "Anti-debug",
    "antidebug_guardpages": "Anti-debug",
    "antidebug_ntcreatethreadex": "Anti-debug",
    "antidebug_ntsetinformationthread": "Anti-debug",
    "antidebug_outputdebugstring": "Anti-debug",
    "antidebug_setunhandledexceptionfilter": "Anti-debug",
    "antidebug_windows": "Anti-debug",
    "antiemu_windefend": "Anti-emulation",
    "antiemu_wine_func": "Anti-emulation",
    "antiemu_wine_reg": "Anti-emulation",
    "antisandbox_check_userdomain": "Anti-sandbox",
    "antisandbox_cuckoo": "Anti-sandbox",
    "antisandbox_cuckoo_files": "Anti-sandbox",
    "antisandbox_cuckoocrash": "Anti-sandbox",
    "antisandbox_foregroundwindows": "Anti-sandbox",
    "antisandbox_fortinet_files": "Anti-sandbox",
    "antisandbox_joe_anubis_files": "Anti-sandbox",
    "antisandbox_mouse_hook": "Anti-sandbox",
    "antisandbox_restart": "Anti-sandbox",
    "antisandbox_sboxie_libs": "Anti-sandbox",
    "antisandbox_sboxie_mutex": "Anti-sandbox",
    "antisandbox_sboxie_objects": "Anti-sandbox",
    "antisandbox_script_timer": "Anti-sandbox",
    "antisandbox_sleep": "Anti-sandbox",
    "antisandbox_sunbelt_files": "Anti-sandbox",
    "antisandbox_sunbelt_libs": "Anti-sandbox",
    "antisandbox_suspend": "Anti-sandbox",
    "antisandbox_threattrack_files": "Anti-sandbox",
    "antisandbox_unhook": "Anti-sandbox",
    "antivirus_clamav": "Antivirus",
    "antivirus_virustotal": "Antivirus",
    "antivm_bochs_keys": "Anti-vm",
    "antivm_directory_objects": "Anti-vm",
    "antivm_generic_bios": "Anti-vm",
    "antivm_generic_cpu": "Anti-vm",
    "antivm_generic_disk": "Anti-vm",
    "antivm_generic_disk_setupapi": "Anti-vm",
    "antivm_generic_diskreg": "Anti-vm",
    "antivm_generic_scsi": "Anti-vm",
    "antivm_generic_services": "Anti-vm",
    "antivm_generic_system": "Anti-vm",
    "antivm_hyperv_keys": "Anti-vm",
    "antivm_network_adapters": "Anti-vm",
    "antivm_parallels_keys": "Anti-vm",
    "antivm_vbox_devices": "Anti-vm",
    "antivm_vbox_files": "Anti-vm",
    "antivm_vbox_keys": "Anti-vm",
    "antivm_vbox_libs": "Anti-vm",
    "antivm_vbox_provname": "Anti-vm",
    "antivm_vbox_window": "Anti-vm",
    "antivm_vmware_devices": "Anti-vm",
    "antivm_vmware_events": "Anti-vm",
    "antivm_vmware_files": "Anti-vm",
    "antivm_vmware_keys": "Anti-vm",
    "antivm_vmware_libs": "Anti-vm",
    "antivm_vmware_mutexes": "Anti-vm",
    "antivm_vpc_files": "Anti-vm",
    "antivm_vpc_keys": "Anti-vm",
    "antivm_vpc_mutex": "Anti-vm",
    "antivm_xen_keys": "Anti-vm",
    "api_spamming": "Anti-analysis",
    "apocalypse_stealer_file_behavior": "Infostealer",
    "arkei_files": "Rat",
    "azorult_mutexes": "Infostealer",
    "bad_certs": "Static",
    "bad_ssl_certs": "Network",
    "banker_cridex": "Banker",
    "banker_prinimalka": "Banker",
    "banker_spyeye_mutexes": "Banker",
    "banker_zeus_mutex": "Banker",
    "banker_zeus_p2p": "Banker",
    "banker_zeus_url": "Banker",
    "bcdedit_command": "Generic",
    "betabot_behavior": "Trojan",
    "bitcoin_opencl": "Cryptomining",
    "blacknet_mutexes": "Rat",
    "blackrat_apis": "Rat",
    "blackrat_mutexes": "Rat",
    "blackrat_network_activity": "Rat",
    "blackrat_registry_keys": "Rat",
    "bootkit": "Rootkit",
    "bot_athenahttp": "Bot",
    "bot_dirtjumper": "Bot",
    "bot_drive": "Bot",
    "bot_drive2": "Bot",
    "bot_kraken_mutexes": "Bot",
    "bot_madness": "Bot",
    "bot_russkill": "Bot",
    "browser_addon": "Browser",
    "browser_helper_object": "Browser",
    "browser_needed": "Generic",
    "browser_scanbox": "Exploit",
    "browser_security": "Browser",
    "browser_startpage": "Browser",
    "bypass_firewall": "Bypass",
    "cape_extracted_content": "Banker",
    "captures_screenshot": "Infostealer",
    "carberp_mutex": "Banker",
    "cerber_behavior": "Ransomware",
    "changes_trust_center_settings": "Evasion",
    "chimera_behavior": "Trojan",
    "clears_logs": "Stealth",
    "clickfraud_cookies": "Clickfraud",
    "clickfraud_volume": "Clickfraud",
    "cmdline_forfiles_wildcard": "Command",
    "cmdline_http_link": "Command",
    "cmdline_long_string": "Command",
    "cmdline_obfuscation": "Command",
    "cmdline_process_discovery": "Discovery",
    "cmdline_reversed_http_link": "Command",
    "cmdline_switches": "Command",
    "cmdline_terminate": "Command",
    "codelux_behavior": "Keylogger",
    "copies_self": "Persistence",
    "crat_mutexes": "Rat",
    "creates_exe": "Generic",
    "creates_largekey": "Stealth",
    "creates_nullvalue": "Stealth",
    "createtoolhelp32snapshot_module_enumeration": "Discovery",
    "critical_process": "Generic",
    "cryptbot_files": "Infostealer",
    "cryptbot_network": "Infostealer",
    "cryptomining_stratum_command": "Cryptomining",
    "cryptomix_mutexes": "Ransomware",
    "cryptopool_domains": "Cryptomining",
    "cryptowall_behavior": "Ransomware",
    "cve_2014_6332": "Exploit Kit",
    "cve_2015_2419_js": "Exploit",
    "cve_2016-0189": "Exploit Kit",
    "cve_2016_7200": "Exploit Kit",
    "cypherit_mutexes": "Trojan",
    "darkcomet_regkeys": "Rat",
    "datop_loader": "Loader",
    "dcrat_behavior": "Infostealer",
    "dcrat_files": "Infostealer",
    "dcrat_mutexes": "Infostealer",
    "dead_connect": "Network",
    "dead_link": "Generic",
    "debugs_self": "Stealth",
    "decoy_document": "Exploit",
    "decoy_image": "Stealth",
    "deepfreeze_mutex": "Anti-sandbox",
    "deletes_executed_files": "Persistence",
    "deletes_self": "Persistence",
    "deletes_shadow_copies": "Ransomware",
    "deletes_system_state_backup": "Ransomware",
    "dep_bypass": "Exploit",
    "dep_disable": "Exploit",
    "dharma_mutexes": "Ransomware",
    "direct_hdd_access": "Bootkit",
    "disables_folder_options": "Generic",
    "disables_run_command": "Generic",
    "disables_app_launch": "Stealth",
    "disables_appv_virtualization": "Ransomware",
    "disables_auto_app_termination": "Ransomware",
    "disables_backups": "Ransomware",
    "disables_browser_warn": "Generic",
    "disables_context_menus": "Ransomware",
    "disables_cpl_disable": "Ransomware",
    "disables_event_logging": "Evasion",
    "disables_mappeddrives_autodisconnect": "Ransomware",
    "disables_notificationcenter": "Generic",
    "disables_power_options": "Ransomware",
    "disables_restore_default_state": "Ransomware",
    "disables_security": "Generic",
    "disables_smartscreen": "Generic",
    "disables_spdy": "Generic",
    "disables_startmenu_search": "Ransomware",
    "disables_system_restore": "Ransomware",
    "disables_uac": "Generic",
    "disables_vba_trust_access": "Evasion",
    "disables_wer": "Stealth",
    "disables_wfp": "Generic",
    "disables_windows_defender": "Anti-av",
    "disables_windows_defender_logging": "Anti-av",
    "disables_windows_file_protection": "Evasion",
    "disables_windowsupdate": "Generic",
    "disables_winfirewall": "Generic",
    "dll_load_uncommon_file_types": "Anti-debug",
    "document_script_exe_drop": "Dropper",
    "dotnet_clr_usagelog_regkeys": "Evasion",
    "dotnet_code_compile": "Evasion",
    "dotnet_csc_build": "Command",
    "downloader_cabby": "Downloader",
    "downloads_from_filehosting": "Loader",
    "dridex_behavior": "Banker",
    "driver_filtermanager": "Stealth",
    "driver_load": "Stealth",
    "dropper": "Dropper",
    "dynamic_function_loading": "Anti-debug",
    "dyre_behavior": "Banker",
    "echelon_files": "Infostealer",
    "enables_wdigest": "Persistence",
    "encrypt_data_agenttesla_http": "Keylogger",
    "encrypt_data_agentteslat2_http": "Keylogger",
    "encrypt_data_nanocore": "Keylogger",
    "encrypt_pcinfo": "C2",
    "encrypted_ioc": "Encryption",
    "enumerates_running_processes": "Discovery",
    "excel4_macro_urls": "Macro",
    "exe_dropper_js": "Dropper",
    "exec_crash": "Execution",
    "exploit_getbasekerneladdress": "Exploit",
    "exploit_gethaldispatchtable": "Exploit",
    "exploit_heapspray": "Exploit",
    "explorer_http": "Masquerading",
    "family_proxyback": "Malware",
    "file_credential_store_access": "Credential Access",
    "file_credential_store_write": "Credential Access",
    "firefox_disables_process_tab": "Banker",
    "fleercivet_mutex": "Trojan",
    "fonix_mutexes": "Ransomware",
    "gandcrab_mutexes": "Ransomware",
    "generates_crypto_key": "Generic",
    "generic_metrics": "Generic",
    "generic_phish": "Network",
    "geodo_banking_trojan": "Banker",
    "germanwiper_mutexes": "Ransomware",
    "get_clipboard_data": "Generic",
    "gondad_js": "Exploit Kit",
    "gootkit_behavior": "Trojan",
    "guloader_apis": "Downloader",
    "gulpix_behavior": "Malware",
    "h1n1_behavior": "Dropper",
    "hancitor_behavior": "Downloader",
    "hawkeye_behavior": "Trojan",
    "heapspray_js": "Exploit",
    "hides_recycle_bin_icon": "Ransomware",
    "http_request": "Network",
    "https_urls": "Network",
    "ie_disables_process_tab": "Banker",
    "ie_martian_children": "Martians",
    "infostealer_bitcoin": "Infostealer",
    "infostealer_browser": "Infostealer",
    "infostealer_browser_password": "Infostealer",
    "infostealer_cookies": "Infostealer",
    "infostealer_ftp": "Infostealer",
    "infostealer_im": "Infostealer",
    "infostealer_keylog": "Infostealer",
    "infostealer_mail": "Infostealer",
    "injection_createremotethread": "Injection",
    "injection_create_remote_thread": "Injection", # CAPE
    "injection_explorer": "Injection",
    "injection_inter_process": "Injection",
    "injection_needextension": "Injection",
    "injection_network_traffic": "Injection",
    "injection_process_hollowing": "Injection",
    "injection_runpe": "Injection",
    "injection_rwx": "Injection",
    "injection_themeinitapihook": "Injection",
    "internet_dropper": "Network",
    "invalid_authenticode_signature": "Static",
    "ipc_namedpipe": "Generic",
    "java_js": "Exploit Kit",
    "js_phish": "Phishing",
    "js_suspicious_redirect": "Exploit Kit",
    "karagany_files": "Rat",
    "karagany_system_event_objects": "Rat",
    "kazybot_behavior": "Rat",
    "kelihos_behavior": "Bot",
    "ketrican_regkeys": "Malware",
    "kibex_behavior": "Keylogger",
    "koadic_apis": "Exploit",
    "koadic_network_activity": "Exploit",
    "kovter_behavior": "Clickfraud",
    "limerat_mutexes": "Rat",
    "limerat_regkeys": "Rat",
    "locker_regedit": "Locker",
    "locker_taskmgr": "Locker",
    "locky_behavior": "Ransomware",
    "lodarat_file_behavior": "Rat",
    "log4shell": "Malware",
    "lokibot_mutexes": "Trojan",
    "long_commandline": "Command",
    "lsa_tampering": "Persistence",
    "lsass_credential_dumping": "Persistence",
    "malicious_dynamic_function_loading": "Malware",
    "mapped_drives_uac": "Generic",
    "masquerade_process_name": "Masquerading",
    "mass_data_encryption": "Encryption",
    "masslogger_artifacts": "Infostealer",
    "masslogger_files": "Infostealer",
    "masslogger_version": "Infostealer",
    "medusalocker_mutexes": "Ransomware",
    "medusalocker_regkeys": "Ransomware",
    "mimics_agent": "Stealth",
    "mimics_extension": "Stealth",
    "mimics_filetime": "Generic",
    "mimics_icon": "Stealth",
    "mimikatz_modules": "Lateral",
    "modify_attachment_manager": "Anti-av",
    "modify_certs": "Browser",
    "modify_desktop_wallpaper": "Ransomware",
    "modify_hostfile": "Generic",
    "modify_oem_information": "Ransomware",
    "modify_proxy": "Browser",
    "modify_security_center_warnings": "Stealth",
    "modify_uac_prompt": "Stealth",
    "modify_zoneid_ads": "Generic",
    "modirat_behavior": "Rat",
    "move_file_on_reboot": "Malware",
    "multiple_explorer_instances": "Command",
    "multiple_useragents": "Network",
    "nemty_mutexes": "Ransomware",
    "nemty_network_activity": "Ransomware",
    "nemty_note": "Ransomware",
    "nemty_regkeys": "Ransomware",
    "neshta_files": "Virus",
    "neshta_mutexes": "Virus",
    "neshta_regkeys": "Virus",
    "netwire_behavior": "Rat",
    "network_anomaly": "Network",
    "network_bind": "Network",
    "network_cnc_http": "Network",
    "network_cnc_https_archive": "Network",
    "network_cnc_https_free_webshoting": "Network",
    "network_cnc_https_generic": "Network",
    "network_cnc_https_pastesite": "Network",
    "network_cnc_https_payload": "Network",
    "network_cnc_https_socialmedia": "Network",
    "network_cnc_https_telegram": "Network",
    "network_cnc_https_temp_urldns": "Network",
    "network_cnc_https_tempstorage": "Network",
    "network_cnc_https_urlshortener": "Network",
    "network_cnc_https_useragent": "Network",
    "network_cnc_smtps_exfil": "Network",
    "network_cnc_smtps_generic": "Network",
    "network_country_distribution": "Network",
    "network_dga": "Network",
    "network_dga_fraunhofer": "Network",
    "network_dns_blockchain": "Network",
    "network_dns_doh_tls": "Network",
    "network_dns_idn": "Network",
    "network_dns_opennic": "Network",
    "network_dns_paste_site": "Network",
    "network_dns_reverse_proxy": "Network",
    "network_dns_suspicious_querytype": "Network",
    "network_dns_temp_file_storage": "Network",
    "network_dns_temp_urldns": "Network",
    "network_dns_tunneling_request": "Network",
    "network_dns_url_shortener": "Network",
    "network_document_file": "Network",
    "network_downloader_exe": "Exploit",
    "network_dyndns": "Network",
    "network_document_http": "Virus",
    "network_excessive_udp": "C2",
    "network_fake_useragent": "Network",
    "network_http": "Network",
    "network_http_post": "Network",
    "network_icmp": "Network",
    "network_ip_exe": "Network",
    "network_irc": "Network",
    "network_multiple_direct_ip_connections": "Network",
    "network_open_proxy": "Network",
    "network_p2p": "Network",
    "network_questionable_host": "Network",
    "network_questionable_http_path": "Network",
    "network_questionable_https_path": "Network",
    "network_smtp": "Network",
    "network_tor": "Network",
    "network_tor_service": "Network",
    "network_torgateway": "Network",
    "neutrino_js": "Exploit Kit",
    "njrat_regkeys": "Rat",
    "nuclear_js": "Exploit Kit",
    "nymaim_behavior": "Trojan",
    "obliquerat_files": "Rat",
    "obliquerat_mutexes": "Rat",
    "obliquerat_network_activity": "Rat",
    "odbcconf_bypass": "Bypass",
    "office_addinloading": "Office",
    "office_anomalous_feature": "Office",
    "office_code_page": "Office",
    "office_com_load": "Office",
    "office_cve2017_11882": "Exploit",
    "office_cve2017_11882_network": "Exploit",
    "office_cve_2021_40444": "Virus",
    "office_cve_2021_40444_m2": "Virus",
    "office_dde_command": "Office",
    "office_dotnet_load": "Office",
    "office_flash_load": "Exploit",
    "office_macro": "Office",
    "office_macro_autoexecution": "Office",
    "office_macro_ioc": "Office",
    "office_macro_malicious_prediction": "Office",
    "office_macro_suspicious": "Office",
    "office_martian_children": "Martians",
    "office_mshtml_load": "Office",
    "office_perfkey": "Office",
    "office_postscript": "Exploit",
    "office_security": "Office",
    "office_suspicious_processes": "Evasion",
    "office_vb_load": "Office",
    "office_wmi_load": "Office",
    "office_write_exe": "Virus",
    "okrum_mutexes": "Malware",
    "orcusrat_behavior": "Rat",
    "origin_langid": "Static",
    "origin_resource_langid": "Static",
    "overwrites_admin_password": "Account",
    "overwrites_accessibility_utility": "Evasion",
    "owa_web_shell_files": "Command",
    "packer_armadillo_mutex": "Packer",
    "packer_armadillo_regkey": "Packer",
    "packer_aspack": "Packer",
    "packer_aspirecrypt": "Packer",
    "packer_bedsprotector": "Packer",
    "packer_confuser": "Packer",
    "packer_enigma": "Packer",
    "packer_entropy": "Packer",
    "packer_mpress": "Packer",
    "packer_nate": "Packer",
    "packer_nspack": "Packer",
    "packer_smartassembly": "Packer",
    "packer_spices": "Packer",
    "packer_themida": "Packer",
    "packer_titan": "Packer",
    "packer_unknown_pe_section_name": "Packer",
    "packer_upx": "Packer",
    "packer_vmprotect": "Packer",
    "packer_yoda": "Packer",
    "parallax_mutexes": "Rat",
    "pdf_annot_urls": "Static",
    "pe_compile_timestomping": "Generic",
    "persistence_ads": "Persistence",
    "persistence_autorun": "Persistence",
    "persistence_autorun_tasks": "Persistence",
    "persistence_bootexecute": "Persistence",
    "persistence_ifeo": "Persistence",
    "persistence_rdp_registry": "Persistence",
    "persistence_rdp_shadowing": "Persistence",
    "persistence_registry_script": "Persistence",
    "persistence_safeboot": "Persistence",
    "persistence_service": "Persistence",
    "persistence_shim_database": "Persistence",
    "persistence_slient_process_exit": "Persistence",
    "persists_dev_util": "Masquerading",
    "phorpiex_mutexes": "Downloader",
    "physical_drive_access": "Bootkit",
    "polymorphic": "Persistence",
    "pony_behavior": "Trojan",
    "potential_overwrite_mbr": "Bootkit",
    "poullight_files": "Infostealer",
    "powerpool_mutexes": "Trojan",
    "powershell_command_suspicious": "Command",
    "powershell_download": "Downloader",
    "powershell_network_connection": "Downloader",
    "powershell_renamed": "Command",
    "powershell_renamed_commandline": "Command",
    "powershell_request": "Downloader",
    "powershell_reversed": "Command",
    "powershell_scriptblock_logging": "Command",
    "powershell_variable_obfuscation": "Command",
    "prevents_safeboot": "Generic",
    "process_creation_suspicious_location": "Execution",
    "process_interest": "Generic",
    "process_needed": "Generic",
    "procmem_yara": "Malware",
    "protonbot_mutexes": "Loader",
    "punch_plus_plus_pcres": "Network",
    "purplewave_mutexes": "Infostealer",
    "purplewave_network_activity": "Infostealer",
    "pysa_mutexes": "Ransomware",
    "quilclipper_behavior": "Infostealer",
    "quilclipper_mutexes": "Infostealer",
    "qulab_files": "Infostealer",
    "qulab_mutexes": "Infostealer",
    "raccoon_behavior": "Infostealer",
    "ransomware_dmalocker": "Ransomware",
    "ransomware_extensions": "Ransomware",
    "ransomware_file_modifications": "Ransomware",
    "ransomware_files": "Ransomware",
    "ransomware_message": "Ransomware",
    "ransomware_radamant": "Ransomware",
    "ransomware_recyclebin": "Ransomware",
    "ransomware_revil_regkey": "Persistence",
    "rat_beebus_mutexes": "Rat",
    "rat_fynloski_mutexes": "Rat",
    "rat_luminosity": "Rat",
    "rat_nanocore": "Rat",
    "rat_pcclient": "Rat",
    "rat_plugx_mutexes": "Rat",
    "rat_poisonivy_mutexes": "Rat",
    "rat_quasar_mutexes": "Rat",
    "rat_senna_mutexes": "Rat",
    "rat_spynet": "Rat",
    "rat_xtreme_mutexes": "Rat",
    "ratsnif_mutexes": "Trojan",
    "rdptcp_key": "Persistence",
    "reads_self": "Generic",
    "recon_beacon": "Network",
    "recon_checkip": "Discovery",
    "recon_fingerprint": "Discovery",
    "recon_programs": "Discovery",
    "recon_systeminfo": "Discovery",
    "registry_credential_dumping": "Persistence",
    "registry_credential_store_access": "Persistence",
    "registry_lsa_secrets_access": "Credential Dumping",
    "regsvr32_squiblydoo_dll_load": "Bypass",
    "remcos_files": "Rat",
    "remcos_mutexes": "Rat",
    "remcos_regkeys": "Rat",
    "removes_networking_icon": "Ransomware",
    "removes_pinned_programs": "Ransomware",
    "removes_security_maintenance_icon": "Ransomware",
    "removes_startmenu_defaults": "Ransomware",
    "removes_username_startmenu": "Ransomware",
    "removes_windows_defender_contextmenu": "Anti-av",
    "removes_zoneid_ads": "Generic",
    "renamer_mutexes": "Trojan",
    "revil_mutexes": "Ransomware",
    "rig_js": "Exploit Kit",
    "rtf_anomaly_characterset": "Office",
    "rtf_anomaly_version": "Office",
    "rtf_aslr_bypass": "Office",
    "rtf_embedded_content": "Office",
    "rtf_embedded_office_file": "Office",
    "rtf_exploit_static": "Exploit",
    "satan_mutexes": "Ransomware",
    "scrcons_wmi_script_consumer": "Command",
    "script_created_process": "Downloader",
    "script_network_activity": "Downloader",
    "script_tool_executed": "Command",
    "secure_login_phishing": "Phishing",
    "securityxploded_modules": "Infostealer",
    "set_clipboard_data": "Generic",
    "sets_autoconfig_url": "Network",
    "shifu_behavior": "Banker",
    "silverlight_js": "Exploit Kit",
    "snake_ransom_mutexes": "Ransomware",
    "sniffer_winpcap": "Network",
    "sodinokibi_behavior": "Ransomware",
    "spawns_dev_util": "Masquerading",
    "spicyhotpot_behavior": "Rootkit",
    "spoofs_procname": "Stealth",
    "spooler_access": "Evasion",
    "spooler_svc_start": "Command",
    "spreading_autoruninf": "Persistence",
    "squiblydoo_bypass": "Bypass",
    "squiblytwo_bypass": "Bypass",
    "stack_pivot": "Exploit",
    "stack_pivot_file_created": "Exploit",
    "stack_pivot_process_create": "Exploit",
    "static_authenticode": "Static",
    "static_dotnet_anomaly": "Static",
    "static_java": "Static",
    "static_pdf": "Static",
    "static_pe_anomaly": "Static",
    "static_pe_pdbpath": "Static",
    "static_rat_config": "Static",
    "static_versioninfo_anomaly": "Static",
    "stealth_childproc": "Stealth",
    "stealth_file": "Stealth",
    "stealth_hidden_extension": "Stealth",
    "stealth_hiddenreg": "Stealth",
    "stealth_hide_notifications": "Stealth",
    "stealth_network": "Stealth",
    "stealth_system_procname": "Stealth",
    "stealth_timeout": "Stealth",
    "stealth_webhistory": "Stealth",
    "stealth_window": "Stealth",
    "stop_ransom_mutexes": "Ransomware",
    "stop_ransomware_cmd": "Ransomware",
    "stop_ransomware_registry": "Ransomware",
    "sundown_js": "Exploit Kit",
    "suricata_alert": "Network",
    "suspicious_certutil_use": "Command",
    "suspicious_command_tools": "Command",
    "suspicious_ioctl_scsipassthough": "Bootkit",
    "suspicious_js_script": "Downloader",
    "suspicious_mpcmdrun_use": "Command",
    "suspicious_ping_use": "Command",
    "suspicious_tld": "Network",
    "sysinternals_psexec": "Command",
    "sysinternals_tools": "Command",
    "system_account_discovery_cmd": "Discovery",
    "system_info_discovery_cmd": "Discovery",
    "system_info_discovery_pwsh": "Discovery",
    "system_network_discovery_cmd": "Discovery",
    "system_network_discovery_pwsh": "Discovery",
    "system_user_discovery_cmd": "Discovery",
    "tampers_etw": "Evasion",
    "tampers_powershell_logging": "Evasion",
    "targeted_flame": "Malware",
    "terminates_remote_process": "Persistence",
    "territorial_disputes_sigs": "Generic",
    "tinba_behavior": "Trojan",
    "transacted_hollowing": "Injection",
    "trickbot_mutex": "Banker",
    "trickbot_task_delete": "Banker",
    "trochilusrat_apis": "Rat",
    "troldesh_behavior": "Ransomware",
    "uac_bypass_cmstp": "Bypass",
    "uac_bypass_cmstpcom": "Bypass",
    "uac_bypass_delegateexecute_sdclt": "Bypass",
    "uac_bypass_eventvwr": "Bypass",
    "uac_bypass_fodhelper": "Persistence",
    "upatre_behavior": "Dropper",
    "upatre_files": "Rat",
    "upatre_mutexes": "Rat",
    "ursnif_behavior": "Keylogger",
    "user_enum": "Recon",
    "uses_adfind": "Discovery",
    "uses_ms_protocol": "Evasion",
    "uses_powershell_copyitem": "Evasion",
    "uses_rdp_clip": "Command",
    "uses_remote_desktop_session": "Command",
    "uses_windows_utilities": "Command",
    "uses_windows_utilities_appcmd": "Evasion",
    "uses_windows_utilities_cipher": "Command",
    "uses_windows_utilities_clickonce": "Command",
    "uses_windows_utilities_csvde_ldifde": "Discovery",
    "uses_windows_utilities_dsquery": "Discovery",
    "uses_windows_utilities_esentutl": "Evasion",
    "uses_windows_utilities_finger": "Evasion",
    "uses_windows_utilities_mode": "Command",
    "uses_windows_utilities_nltest": "Discovery",
    "uses_windows_utilities_ntdsutil": "Discovery",
    "uses_windows_utilities_to_create_scheduled_task": "Command",
    "uses_windows_utilities_xcopy": "Evasion",
    "vawtrak_behavior": "Banker",
    "venomrat_mutexes": "Rat",
    "vidar_behavior": "Infostealer",
    "virtualcheck_js": "Exploit Kit",
    "virus": "Virus",
    "volatility_devicetree_1": "Generic",
    "volatility_handles_1": "Generic",
    "volatility_ldrmodules_1": "Generic",
    "volatility_ldrmodules_2": "Generic",
    "volatility_malfind_1": "Generic",
    "volatility_malfind_2": "Generic",
    "volatility_modscan_1": "Generic",
    "volatility_svcscan_1": "Generic",
    "volatility_svcscan_2": "Generic",
    "volatility_svcscan_3": "Generic",
    "warzonerat_files": "Rat",
    "warzonerat_regkeys": "Rat",
    "web_shell_files": "Command",
    "web_shell_processes": "Command",
    "webmail_phish": "Network",
    "whois_create": "Network",
    "win32_process_create": "Martians",
    "windows_defender_powershell": "Anti-av",
    "wiper_zeroedbytes": "Malware",
    "wmi_create_process": "Martians",
    "wmi_script_process": "Martians",
    "wmic_command_suspicious": "Command",
    "writes_sysvol": "Credential Access",
    "xpertrat_files": "Rat",
    "xpertrat_mutexes": "Rat",
}

CAPE_SIGNATURE_CATEGORIES = {
    "Account": {
        "id": 1,
        "description": "Adds or manipulates an administrative user account.",
    },
    "Anti-analysis": {
        "id": 2,
        "description": "Constructed to conceal or obfuscate itself to prevent analysis.",
    },
    "Anti-av": {
        "id": 3,
        "description": "Attempts to conceal itself from detection by antivirus.",
    },
    "Anti-debug": {
        "id": 4,
        "description": "Attempts to detect if it is being debugged.",
    },
    "Anti-emulation": {"id": 5, "description": "Detects the presence of an emulator."},
    "Anti-sandbox": {
        "id": 6,
        "description": "Attempts to detect if it is in a sandbox.",
    },
    "Anti-vm": {
        "id": 7,
        "description": "Attempts to detect if it is being run in virtualized environment.",
    },
    "Antivirus": {"id": 8, "description": "AntiVirus hit. File is infected."},
    "Banker": {
        "id": 9,
        "description": (
            "Designed to gain access to confidential information stored or processed through online banking."
        ),
    },
    "Bootkit": {
        "id": 10,
        "description": "Manipulates machine configurations that would affect the boot of the machine.",
    },
    "Bot": {
        "id": 11,
        "description": "Appears to be a bot or exhibits bot-like behaviour.",
    },
    "Browser": {
        "id": 12,
        "description": "Manipulates browser-settings in a suspicious way.",
    },
    "Bypass": {
        "id": 13,
        "description": "Attempts to bypass operating systems security controls (firewall, amsi, applocker, etc.)",
    },
    "C2": {
        "id": 14,
        "description": "Communicates with a server controlled by a malicious actor.",
    },
    "Clickfraud": {
        "id": 15,
        "description": "Manipulates browser settings to allow for insecure clicking.",
    },
    "Command": {"id": 16, "description": "A suspicious command was observed."},
    "Credential Access": {
        "id": 17,
        "description": "Uses techniques to access credentials.",
    },
    "Credential Dumping": {
        "id": 18,
        "description": "Uses techniques to dump credentials.",
    },
    "Cryptomining": {
        "id": 19,
        "description": "Facilitates mining of cryptocurrency.",
    },
    "Discovery": {
        "id": 20,
        "description": "Uses techniques for discovery information about the system, the user, or the environment.",
    },
    "Dns": {"id": 21, "description": "Uses suspicious DNS queries."},
    "Dotnet": {"id": 22, "description": ".NET code is used in a suspicious manner."},
    "Downloader": {"id": 23, "description": "Trojan that downloads installs files."},
    "Dropper": {
        "id": 24,
        "description": "Trojan that drops additional malware on an affected system.",
    },
    "Encryption": {
        "id": 25,
        "description": "Encryption algorithms are used for obfuscating data.",
    },
    "Evasion": {"id": 26, "description": "Techniques are used to avoid detection."},
    "Execution": {
        "id": 27,
        "description": "Uses techniques to execute harmful code or create executables that could run harmful code.",
    },
    "Exploit": {
        "id": 28,
        "description": "Exploits an known software vulnerability or security flaw.",
    },
    "Exploit Kit": {
        "id": 29,
        "description": "Programs designed to crack or break computer and network security measures.",
    },
    "Generic": {
        "id": 30,
        "description": "Basic operating system objects are used in suspicious ways.",
    },
    "Infostealer": {
        "id": 31,
        "description": "Collects and disseminates information such as login details, usernames, passwords, etc.",
    },
    "Injection": {
        "id": 32,
        "description": (
            "Input is not properly validated and gets processed by an interpreter as part of a command or query."
        ),
    },
    "Keylogger": {"id": 33, "description": "Monitoring software detected."},
    "Lateral": {
        "id": 34,
        "description": "Techniques used to move through environment and maintain access.",
    },
    "Loader": {
        "id": 35,
        "description": "Download and execute additional payloads on compromised machines.",
    },
    "Locker": {"id": 36, "description": "Prevents access to system data and files."},
    "Macro": {
        "id": 37,
        "description": (
            "A set of commands that automates a software to perform a certain action, found in Office macros."
        ),
    },
    "Malware": {
        "id": 38,
        "description": "The file uses techniques associated with malicious software.",
    },
    "Martians": {
        "id": 39,
        "description": "Command shell or script process was created by unexpected parent process.",
    },
    "Masquerading": {
        "id": 40,
        "description": "The name or location of an object is manipulated to evade defenses and observation.",
    },
    "Network": {"id": 41, "description": "Suspicious network traffic was observed."},
    "Office": {
        "id": 42,
        "description": "Makes API calls not consistent with expected/standard behaviour.",
    },
    "Packer": {
        "id": 43,
        "description": "Compresses, encrypts, and/or modifies a malicious file's format.",
    },
    "Persistence": {
        "id": 44,
        "description": (
            "Technique used to maintain presence in system(s) across interruptions that could cut off access."
        ),
    },
    "Phishing": {
        "id": 45,
        "description": "Techniques were observed that attempted to obtain information from the user.",
    },
    "Ransomware": {
        "id": 46,
        "description": "Designed to block access to a system until a sum of money is paid.",
    },
    "Rat": {
        "id": 47,
        "description": (
            "Designed to provide the capability of covert surveillance and/or unauthorized access to a target."
        ),
    },
    "Rootkit": {
        "id": 48,
        "description": (
            "Designed to provide continued privileged access to a system while actively hiding its presence."
        ),
    },
    "Static": {
        "id": 51,
        "description": "A suspicious characteristic was discovered during static analysis.",
    },
    "Stealth": {
        "id": 52,
        "description": "Leverages/modifies internal processes and settings to conceal itself.",
    },
    "Trojan": {
        "id": 53,
        "description": "Presents itself as legitimate in attempt to infiltrate a system.",
    },
    "Virus": {"id": 54, "description": "Malicious software program."},
}

# These are too noisy to be considered useful.
CAPE_DROPPED_SIGNATURES = [
    "powershell_scriptblock_logging",
    "antidebug_setunhandledexceptionfilter",
    "dynamic_function_loading",
    "stealth_timeout",
]


def get_category_id(sig: str) -> int:
    """
    This method returns the category ID for a given signature name
    :param sig: given signature name
    :return: the category ID
    """
    category = CAPE_SIGNATURES.get(sig, "unknown")
    metadata = CAPE_SIGNATURE_CATEGORIES.get(category, {})
    return metadata.get("id", 9999)


def get_signature_category(sig: str) -> str:
    """
    This method returns the category for a given signature name
    :param sig: given signature name
    :return: The category name
    """
    return CAPE_SIGNATURES.get(sig, "unknown")


SIGNATURE_TO_ATTRIBUTE_ACTION_MAP = {
    # Signature Name : attribute action that is relevant
    "dead_connect": "network_connection",
    "antidebug_setunhandledexceptionfilter": "process_tampering",
    "dynamic_function_loading": "driver_loaded",
    "process_needed": "process_access",
    "injection_network_traffic": "network_connection",
    "explorer_http": "network_connection",
    "deletes_self": "file_delete",
    "removes_zoneid_ads": "registry_delete",
}
