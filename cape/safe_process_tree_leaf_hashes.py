SAFE_PROCESS_TREE_LEAF_HASHES = {
    "d3b14a95c2160abc76f356b5e9b79c71c91035e49f1c5962ce7a100e61decd78": {
        "image": "?sys32\\lsass.exe",
        "command_line": "C:\\WINDOWS\\system32\\lsass.exe",
        "children": []
    },
    "f405c23c52c0dd0cd7ac31f92df0e76f9c6702b155ca5be6afbc076bb81d82a6": {
        "image": "?pf86\\common files\\microsoft shared\\officesoftwareprotectionplatform\\osppsvc.exe",
        "command_line": "\"C:\\Program Files\\Common Files\\Microsoft Shared\\OfficeSoftwareProtectionPlatform\\OSPPSVC.EXE\"",
        "children": []
    },
    "a1d7889895b3a83edb3306c85df424da544369567d860215a75f5cbffe635375": {
        "image": '?sys32\\lsass.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\services.exe',
                "command_line": None,
                "children": [
                    {
                        "image": "?pf86\\common files\\microsoft shared\\officesoftwareprotectionplatform\\osppsvc.exe",
                        "command_line": "\"C:\\Program Files\\Common Files\\Microsoft Shared\\OfficeSoftwareProtectionPlatform\\OSPPSVC.EXE\"",
                        "children": []
                    }
                ]
            }
        ]
    },
    "7e2c38006c7720d214b726be34bf3bbfca1c8f02c3b36f7c8b7c7198f119c8a2": {
        "image": "?sys32\\sppsvc.exe",
        "command_line": "C:\\Windows\\system32\\sppsvc.exe",
        "children": []
    },
    "2f6044eb59e4d5104cfd7025ffd14fe2bea9405c566f7f4ecc9548f694fad00a": {
        "image": "?sys32\\svchost.exe",
        "command_line": "C:\\WINDOWS\\System32\\svchost.exe -k WerSvcGroup",
        "children": [
            {
                "image": "?sys32\\werfault.exe",
                "command_line": "C:\\WINDOWS\\system32\\WerFault.exe -pss -s 476 -p 3168 -ip 3168",
                "children": []
            }
        ]
    },
    "b04893383338161ca8bec608cb9b877acf5c6708cbc4244ec5d0f49f5ab4b9f1": {
        "image": "?sys32\\slui.exe",
        "command_line": "C:\\WINDOWS\\System32\\slui.exe -Embedding",
        "children": []
    },
    "01bf5d0579b4db52ee0322f9f84b7db238c037a2d32b4969298830612ffbdcf8": {
        "image": "?sys32\\backgroundtaskhost.exe",
        "command_line": "\"C:\\WINDOWS\\system32\\backgroundTaskHost.exe\" -ServerName:App.AppXmtcan0h2tfbfy7k9kn8hbxb6dmzz1zh0.mca",
        "children": []
    },
    "a53afad8f3925d95edace69eb6e68184b3d52bdaae0bacdd2f7df5ede70446a8": {
        "image": "?pf86\\windowsapps\\microsoft.windowscommunicationsapps_16005.13426.20920.0_x64__8wekyb3d8bbwe\\hxtsr.exe",
        "command_line": "\"C:\\Program Files\\WindowsApps\\microsoft.windowscommunicationsapps_16005.13426.20920.0_x64__8wekyb3d8bbwe\\HxTsr.exe\" -ServerName:Hx.IPC.Server",
        "children": []
    },
    "1fc2ec278dbd4f03d4a6ea748d35f75b554e43b8211fc5bcebb2ff295e03182b": {
        "image": "?sys32\\runtimebroker.exe",
        "command_line": "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
        "children": []
    },
    "51b9684487d1a103549ec6f5773e058932073037dc30fdb6580c9c388503cf74": {
        "image": "?sys32\\conhost.exe",
        "command_line": "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff -ForceV1",
        "children": []
    },
    "f3d6ed01b460589fbebaf89c2fcad5503bf4d86993fb20d410eace46a595108f": {
        "image": "?sys32\\svchost.exe",
        "command_line": "C:\\WINDOWS\\System32\\svchost.exe -k WerSvcGroup",
        "children": []
    },
    "d1c20b94425d2d866bdd30adc1af7d7ce5b08c30c7418f618d8164ac06ae76ee": {
        "image": "?sys32\\dllhost.exe",
        "command_line": "C:\\Windows\\system32\\DllHost.exe /Processid:{F9717507-6651-4EDB-BFF7-AE615179BCCF}",
        "children": []
    },
    "9c58c41fb2916bea2d6059e912a55c5505ce0b3b7b78cdf6ee3321387ce0f0ae": {
        "image": "?sys32\\wbem\\wmiprvse.exe",
        "command_line": "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding",
        "children": []
    },
    # FP since we only look at the image here
    # "3e3793b897525f211e7425c45df068b2594bb4ad8dcf731f5771fd30233d721b": {
    #     "image": "?sys32\\rundll32.exe",
    #     "command_line": "C:\\WINDOWS\\system32\\rundll32.exe C:\\WINDOWS\\system32\\PcaSvc.dll,PcaPatchSdbTask",
    #     "children": []
    # },
    "ab2bf0e9666652ed8254b079209e27568e0e55a4418cfe94a48181f34625ff15": {
        "image": "?sys32\\sc.exe",
        "command_line": "C:\\WINDOWS\\system32\\sc.exe start wuauserv",
        "children": [
            {
                "image": "?sys32\\conhost.exe",
                "command_line": "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff -ForceV1",
                "children": []
            }
        ]
    },
    "2dd065baf9009515b0d68a64a7cf324ff325893fb8ca630febed2950a3be7432": {
        "image": "?sys32\\wermgr.exe",
        "command_line": "\"C:\\WINDOWS\\system32\\wermgr.exe\" \"-outproc\" \"0\" \"2720\" \"1936\" \"1868\" \"1940\" \"0\" \"0\" \"0\" \"0\" \"0\" \"0\" \"0\" \"0\"",
        "children": []
    },
    "50c958b80515a739a7a9397890d310a91d1e3593ab1aae7757331d71768ccc4a": {
        "image": "?sys32\\sc.exe",
        "command_line": "C:\\Windows\\system32\\sc.exe start w32time task_started",
        "children": []
    },
    "faac8a70045bd7596a1f1e368e346130e357b6f5e8b043287653dfe1fabb12b9": {
        "image": "?sys32\\sdclt.exe",
        "command_line": "C:\\Windows\\System32\\sdclt.exe /CONFIGNOTIFICATION",
        "children": []
    },
    "d922fb8a674c43236b96805a7ba2d4090f0cb7e6ae12d0186339c9ad489c6386": {
        "image": "?sys32\\taskhost.exe",
        "command_line": "taskhost.exe $(Arg0)",
        "children": []
    },
    "e7a3087aba99f3aa0dd4aa5a44d0be58256b4ef41be49da617026838f5204f5c": {
        "image": "?win\\systemapps\\microsoftwindows.client.cbs_cw5n1h2txyewy\\inputapp\\textinputhost.exe",
        "command_line": "\"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\InputApp\\TextInputHost.exe\" -ServerName:InputApp.AppX9jnwykgrccxc8by3hsrsh07r423xzvav.mca",
        "children": []
    },
    "04184d24f08dadab15c91374f7aedba484d8214d0d3c2e8b240e3b7b6f25d959": {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": "?win\\systemapps\\microsoftwindows.client.cbs_cw5n1h2txyewy\\inputapp\\textinputhost.exe",
                "command_line": "\"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\InputApp\\TextInputHost.exe\" -ServerName:InputApp.AppX9jnwykgrccxc8by3hsrsh07r423xzvav.mca",
                "children": []
            }
        ]
    },
    "24954e76154b030985354403bdb85d0a334c0007c842f5381ed8a0544f11466b": {
        "image": "?sys32\\wbem\\wmiadap.exe",
        "command_line": "wmiadap.exe /F /T /R",
        "children": []
    },
    "a7756c96db89aaf251d32633e40b57c104807060c3f7c650c0b94ea90cb0458b": {
        "image": "?win\\explorer.exe",
        "command_line": "C:\\WINDOWS\\Explorer.EXE",
        "children": [
            {
                "image": "?sys32\\werfault.exe",
                "command_line": "C:\\WINDOWS\\system32\\WerFault.exe -u -p 6080 -s 6792",
                "children": []
            }
        ]
    },
    "aa5dd26518bf22e0d6ca76b67a2295934aa52858ec19b47affadf99cbd328a2e": {
        "image": "?win\\systemapps\\microsoft.windows.startmenuexperiencehost_cw5n1h2txyewy\\startmenuexperiencehost.exe",
        "command_line": "\"C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe\" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca",
        "children": []
    },
    "44dcdb8d08f7fdcfe0843d73a652ddbe1e1729fdfdcb66e8f009d3f82a3103ea": {
        "image": "?win\\systemapps\\microsoft.windows.search_cw5n1h2txyewy\\searchapp.exe",
        "command_line": "\"C:\\Windows\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchApp.exe\" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca",
        "children": []
    },
    "6a27c89bdbe4f9855307c59f8c8a480e9a76681cf533d18690754baa250228db": {
        "image": "?sys32\\mobsync.exe",
        "command_line": "C:\\WINDOWS\\System32\\mobsync.exe -Embedding",
        "children": []
    },
    "b12bbea6f1a504c7288762f649b849457edbee81b4967863dad67f3158b250fb": {
        "image": "?sys32\\musnotifyicon.exe",
        "command_line": "%%systemroot%%\\system32\\MusNotifyIcon.exe NotifyTrayIcon 0",
        "children": []
    },
    "bcb1213942dd880cc729f5b6cad820e1cc0c0c92cdd4ab3e3919edd6e40fbb64": {
        "image": "?pf86\\windowsapps\\microsoft.xboxgamingoverlay_5.621.4222.0_x64__8wekyb3d8bbwe\\gamebar.exe",
        "command_line": "\"C:\\Program Files\\WindowsApps\\Microsoft.XboxGamingOverlay_5.621.4222.0_x64__8wekyb3d8bbwe\\GameBar.exe\" -ServerName:App.AppXbdkk0yrkwpcgeaem8zk81k8py1eaahny.mca",
        "children": []
    },
    "fd4fad363ee4c67ab9826cff5ab63d8a68bde96c63b60d70bc7654d26695e469": {
        "image": "?pf86\\windowsapps\\microsoft.xboxgamingoverlay_5.621.4222.0_x64__8wekyb3d8bbwe\\gamebarftserver.exe",
        "command_line": "\"C:\\Program Files\\WindowsApps\\Microsoft.XboxGamingOverlay_5.621.4222.0_x64__8wekyb3d8bbwe\\GameBarFTServer.exe\" -Embedding",
        "children": []
    },
    "f3de6d0a84196f1af3fe985f772c7a4dd23a7979286e78c9928d3f3fcb090a82": {
        "image": "?sys32\\backgroundtransferhost.exe",
        "command_line": "\"BackgroundTransferHost.exe\" -ServerName:BackgroundTransferHost.1",
        "children": []
    },
    "73eb56621fbdbdfaeb669105ba4eb327854790d55994a23a2f852fed8bf9b9af": {
        "image": "?sys32\\backgroundtaskhost.exe",
        "command_line": "\"C:\\WINDOWS\\system32\\backgroundTaskHost.exe\" -ServerName:App.AppXmtcan0h2tfbfy7k9kn8hbxb6dmzz1zh0.mca",
        "children": [
            {
                "image": "?sys32\\conhost.exe",
                "command_line": "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff -ForceV1",
                "children": []
            }
        ]
    },
    "0e3b8b7c5bbffdf8923f5acd914194d7f5db897b73a0f0541dc13750e4af718a": {
        "image": "?sys32\\werfault.exe",
        "command_line": "C:\\WINDOWS\\system32\\WerFault.exe -pss -s 484 -p 6448 -ip 6448",
        "children": []
    },
    "25a026bdd54385f3aaefb8e1723f5be97b7c36e255b2c48f7f7f8a66d9df7eb8": {
        "image": "?sys32\\waasmedicagent.exe",
        "command_line": "C:\\WINDOWS\\System32\\WaaSMedicAgent.exe 843c17b493dbd4989beed27582c82422 sXMpv2EzyEqV2L6NYnvYjw.0.1.0.0.0",
        "children": []
    },
    "54e726d55dcb6c6c4914a0ae899d89c454442624fa64c824bee9110b4abc7721": {
        "image": "?sys32\\sc.exe",
        "command_line": "C:\\WINDOWS\\system32\\sc.exe start pushtoinstall registration",
        "children": [
            {
                "image": "?sys32\\conhost.exe",
                "command_line": "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff -ForceV1",
                "children": [
                    {
                        "image": "?sys32\\wermgr.exe",
                        "command_line": "\"C:\\WINDOWS\\system32\\wermgr.exe\" \"-outproc\" \"0\" \"1072\" \"1928\" \"1876\" \"1932\" \"0\" \"0\" \"0\" \"0\" \"0\" \"0\" \"0\" \"0\"",
                        "children": []
                    }
                ]
            }
        ]
    },
    "bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073": {
        "image": "system",
        "command_line": None,
        "children": []
    },
    "acbf70b95a96ba178eb89269e7f1db5f622fa4b6b009cd29284d7be14024625b": {
        "image": "?sys32\\searchindexer.exe",
        "command_line": None,
        "children": []
    },
    "49a2ab6c73a10ee6bd97a0ba200c6f6dc0dc2977059b8029579e780748f19c72": {
        "image": "?c\\python27\\pythonw.exe",
        "command_line": None,
        "children": []
    },
    "49d9994a34643bea4cc71a26501d1e58ccabd051a1cf9704184b6374e1ef3764": {
        "image": "?sys32\\searchprotocolhost.exe",
        "command_line": None,
        "children": []
    },
    "a54f2146bd3272b89f7b9c7047f2b436a9514f89feeed754bcc6d19d32dc2db3": {
        "image": "?sys32\\searchfilterhost.exe",
        "command_line": None,
        "children": []
    },
    "1d038671bb56576c62a176c7902e6867a978732d1ecafe792c8ac6ac3dde79ba": {
        "image": "?sys32\\svchost.exe",
        "command_line": None,
        "children": [
            {
                "image": "?win\\explorer.exe",
                "command_line": None,
                "children": []
            }
        ]
    },
    "5f4653a82121522720fbb9bdab186d70bf7f21e1ca475cb87b12f448ea71e1ca": {
        "image": "?sys32\\svchost.exe",
        "command_line": None,
        "children": [
            {
                "image": "?sys32\\conhost.exe",
                "command_line": "\\??\\C:\\Windows\\system32\\conhost.exe \"-28232134049486641315307486691639655269-80106784-108753052346563986-549529209\"",
                "children": []
            }
        ]
    },
    "78f84277f3383d654d64679ea93be5614d09b588006f0e9ca7395bb797a6f942": {
        "image": "?sys32\\svchost.exe",
        "command_line": None,
        "children": [
            {
                "image": '?c\\python27\\pythonw.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    "da60beb532bc62cd2208910c086bcbabc4488d45e2dcc4e8414b3969e7902fc7": {
        "image": "?sys32\\svchost.exe",
        "command_line": None,
        "children": [
            {
                "image": "?sys32\\svchost.exe",
                "command_line": None,
                "children": []
            }
        ]
    },
    "6dea6b390c3611c05f7ce0a8d56b136431168161237ae254f4f0a3eeedb52fa9": {
        "image": "?sys32\\userinit.exe",
        "command_line": None,
        "children": []
    },
    "fe1b33fe682a3ce734f5e66aface2e59bad7a91741a6166b793e1658a44cab7b": {
        "image": "?win\\microsoft.net\\framework64\\v4.0.30319\\mscorsvw.exe",
        "command_line": None,
        "children": []
    },
    "eea8165b1ac8e04a4257e249753f1b8085e712521e3fc44718a49bb94851ff1b": {
        "image": "?win\\microsoft.net\\framework\\v4.0.30319\\mscorsvw.exe",
        "command_line": None,
        "children": []
    },
    "5a5f1f8bf9b80413fff222a0a88c3c52c018f9539f0904590999d46c75df012b": {
        "image": "?sys32\\wevtutil.exe",
        "command_line": None,
        "children": []
    },
    '683045c417897765931f9c4de5799babaf16b2ab34a6a3a30eb442512c7df6cf': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?pf86\\microsoft\\edgeupdate\\microsoftedgeupdate.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    'ca2681bddeb1b3c58f48ab9244d677808317cc73efb553bf6376621456696386': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\wbem\\wmiprvse.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    '34f75b36eb062dd4e2fceecea864aeb679d15099f6b76d46d9e881cdc0c2565f': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?pf86\\windowsapps\\microsoft.yourphone_1.22022.180.0_x64__8wekyb3d8bbwe\\yourphone.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    'd5eaaf0f58b9480f6d77d6f8cc07fc7de6f0100fd9cb20ffffcd4e3755ac2c91': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?win\\microsoft.net\\framework64\\v4.0.30319\\smsvchost.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    '9c1ab7458090e539853fc3467a646f6609bfd65562c493123a0a0bbbf8010756': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\mqsvc.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    'f2917a808064123e3affa565e9bcbe222ed377a586291c5db0c253647c094d44': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\dwm.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    '31c722814723945f3a75457cc44353b4d3569c6a352af85dccafa182c58ad653': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\fontdrvhost.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    'eae18f81f6dd53ad84a780d67f1f91c6f8427e2aba53aeb3617e2c6a64ca6731': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\sihost.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    'aa43ef5d5f78c7017d4ba1ad33b988ca68e2a2635f5010d8c0bc8157816770c2': {
        "image": '?sys32\\ctfmon.exe',
        "command_line": None,
        "children": []
    },
    'f26db097862af031c8a7ab84423f063be7f6e01f50699cdd3bfc23542af6a5b4': {
        "image": '?sys32\\services.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\svchost.exe',
                "command_line": 'C:\\WINDOWS\\System32\\svchost.exe -k netsvcs -p -s BITS',
                "children": []
            }
        ]
    },
    '44e862ebd67cd7ffe848064c41aa16111ec0d95c918bb792d1625df1d98b29aa': {
        "image": '?sys32\\smss.exe',
        "command_line": None,
        "children": []
    },
    '1851240177eab8d1db9cae2a230ba8f46f660b99de4324457bfad2b51346bef5': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\searchfilterhost.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    '444f02be8905f4dc7be2ab190159644baebab2bd8ed351ceb6474ce317440f0c': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\searchprotocolhost.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    '8c173d9b81725561674d18ec4e7c77d21f93b19384b342fbdf1592f5fc6300f3': {
        "image": '?sys32\\svchost.exe',
        "command_line": None,
        "children": [
            {
                "image": '?sys32\\taskhost.exe',
                "command_line": None,
                "children": []
            }
        ]
    },
    '476af2541f60045ea6fb29913f65e83ad506e0377a9ddfaf200683ed0ed0457d': {
        "image": '?sys32\\conhost.exe|?sys32\\cmd.exe',
        "command_line": None,
        "children": []
    },
    'd347dce729508445a629ec5824e89745a78ad5ca4ac5e438a435f5991b40c8cc': {
        "image": '?sys32\\conhost.exe|?sys32\\wevtutil.exe',
        "command_line": None,
        "children": []
    },
    'c59c9356f5b4fe145261f2537853cf3d3e40bda7d687642d502d8a7804b1996b': {
        "image": '?sys32\\conhost.exe|?sys32\\net.exe',
        "command_line": None,
        "children": []
    },
    'f907b893fb58d829ea064101eaea311fc3b349f4df57d98585d2a1e9947db152': {
        "image": '?sys32\\conhost.exe|?sys32\\net1.exe',
        "command_line": 'C:\\Windows\\system32\\net1 stop winmgmt /y',
        "children": []
    },
    '994e09b156ed0844663bfce7510a7473ca574523c874ff47f3ed99f7d096f249': {
        "image": '?sys32\\conhost.exe|?sys32\\sc.exe',
        "command_line": None,
        "children": []
    },
    '6fa48cc6d3ecd1c0f3a16aaa38a3a623da5340b78b0319839d3bd5952357a967': {
        "image": '?sys32\\dinotify.exe',
        "command_line": None,
        "children": []
    },
    'a364a5fcf64b5d9e29ba27262a73ccfbb88725651716677862622411c7d3d2f3': {
        "image": '?sys32\\lsass.exe|?sys32\\services.exe',
        "command_line": None,
        "children": []
    },
    '7ebc8a21cfcc0374fdb80a24a23b21e568ffb58285782b115cde8315f58b3c58': {
        "image": '?usr\\appdata\\local\\programs\\python\\python38-32\\pythonw.exe',
        "command_line": None,
        "children": []
    },
    '2a119d477c12829140fb54e41c8666a0a8a37aa8f71f41a61746e6b7c144d70a': {
        "image": '?sys32\\sppextcomobj.exe',
        "command_line": None,
        "children": []
    },
    '72f73ead06808f10feb9f2fa35900fc8ca7ac1759a8928544251b33a0a6a9056': {
        "image": '?sys32\\net.exe|?sys32\\net1.exe',
        "command_line": None,
        "children": []
    },
    'e1d55007ec820d344a9f4c752bb18d1b096fc3372c515c40a43ac1f2229e95b3': {
        "image": '?sys32\\winlogon.exe|?sys32\\wlrmdr.exe',
        "command_line": None,
        "children": []
    },
    '2ae01e5403fb56f97aace63b3b309cc88cb8906602a60dece33058bbe327d156': {
        "image": '?sys32\\remotefxvgpudisablement.exe',
        "command_line": None,
        "children": []
    },
    'cc02ea74d37fa271b43948cbe04647261f44090145b68b536d455252e9320e45': {
        "image": '?sys32\\conhost.exe|?sys32\\net.exe|?sys32\\conhost.exe',
        "command_line": None,
        "children": []
    },
    'be60898adbbbb25571447e166b7dc47774caa0c08a25b58c702265d9493dd8cf': {
        "image": '?pf86\\microsoft\\edgeupdate\\microsoftedgeupdate.exe',
        "command_line": None,
        "children": []
    },
    'ea90560a25a71393736af6dff232fa4e707745b1e51b9e2d20af68b778a9c462': {
        "image": '?sys32\\taskhostw.exe|?sys32\\taskhostw.exe',
        "command_line": None,
        "children": []
    },
    '94fac187f90124578fcfcd99dbfc76501dcdbb74482cb76e3545ffc50b95827d': {
        "image": '?sys32\\taskhostw.exe|?sys32\\sihost.exe',
        "command_line": None,
        "children": []
    },
    '732a810b6f08ed3fde5cb764c59946a6197c344b36fd56c8abd2a00986a20ac7': {
        "image": '?sys32\\taskhostw.exe|?sys32\\mqsvc.exe',
        "command_line": None,
        "children": []
    },
    'af7d460d7bcc554ac9277ff9f0339d8a939ccee8a22c439d6ba481c9a30ad7ec': {
        "image": '?sys32\\taskhostw.exe|?sys32\\spoolsv.exe',
        "command_line": None,
        "children": []
    },
    '05111d015b9fa4809d79c14b756fd3bf9a55d99833a8dce42217544502bb38ff': {
        "image": '?sys32\\taskhostw.exe|memcompression',
        "command_line": None,
        "children": []
    },
    '1a90f8e75b218ea9801804bfcf3e3e245ddef01314772ab502a29aa16286073c': {
        "image": '?sys32\\taskhostw.exe|?sys32\\upfc.exe',
        "command_line": None,
        "children": []
    },
    '96424b2285f9dd53e399089db665b255e3b55fb08951645ac7f9594613da9344': {
        "image": '?sys32\\taskhostw.exe|?sys32\\dwm.exe',
        "command_line": None,
        "children": []
    },
    'aa403b97e40e054a43c628ff0635fdce84c28e6f6b5e724b3fce7c3616a29241': {
        "image": '?sys32\\taskhostw.exe|?sys32\\fontdrvhost.exe',
        "command_line": None,
        "children": []
    },
    'd101b5a95b6677a23bfad2460447393941496483e55dea5f78c658786abd3e1d': {
        "image": '?sys32\\taskhostw.exe|?sys32\\winlogon.exe',
        "command_line": None,
        "children": []
    },
    'b34be9e65d1916ab9124493b5749a2bacb14f95e5349177a074bd70128726639': {
        "image": '?sys32\\taskhostw.exe|?sys32\\wininit.exe',
        "command_line": None,
        "children": []
    },
    '872491a30d60d598962de6e7b834ab76b2aa65fbab102c6ebaaae6acdc238822': {
        "image": '?sys32\\taskhostw.exe|registry',
        "command_line": None,
        "children": []
    },
    '2b09601d34ebca15ce98aa08221975e013157761a6eb0daec182c51dd92576a1': {
        "image": '?sys32\\net.exe|?sys32\\taskhostw.exe|?sys32\\conhost.exe',
        "command_line": None,
        "children": []
    },
    'b0fc7cd8eb1d40f8b681311f34e84148a338fdeb70e6bf90177a33b11c7e8862': {
        "image": '?sys32\\net.exe|?sys32\\taskhostw.exe|?usr\\appdata\\local\\programs\\python\\python310-32\\pythonw.exe',
        "command_line": None,
        "children": []
    },
    'c22d9355dcb49b568dd8e3b30c2019b5ea3c9c0e502d3bbe0d1c5f0ee405979f': {
        "image": '?sys32\\net.exe|?sys32\\taskhostw.exe|?win\\pyw.exe',
        "command_line": None,
        "children": []
    },
    '03db4481cda2012d040b8c56ce97d547e51be86533df94efaada91db1a296bf4': {
        "image": '?sys32\\net.exe|?sys32\\taskhostw.exe|?sys32\\runtimebroker.exe',
        "command_line": None,
        "children": []
    },
    '2211f2326f9d4302da0fa358d24bd736b628b2d0d4938058bb3e0727d0f3f845': {
        "image": '?sys32\\net.exe|?sys32\\taskhostw.exe|?win\\systemapps\\microsoft.windows.search_cw5n1h2txyewy\\searchapp.exe',
        "command_line": None,
        "children": []
    },
    '276fb6cd289713d8c91031e3a503c267fbec6659ebae2a8f3483b2dff36b6ffd': {
        "image": '?sys32\\net.exe|?sys32\\taskhostw.exe|?win\\systemapps\\microsoft.windows.startmenuexperiencehost_cw5n1h2txyewy\\startmenuexperiencehost.exe',
        "command_line": None,
        "children": []
    },
    'b378c3777df2f27717f2aa11c90b2f81f6f16ea82256ad2258cabe4594e8d8c0': {
        "image": '?sys32\\net.exe|?sys32\\taskhostw.exe|?pf86\\microsoft\\edgeupdate\\microsoftedgeupdate.exe',
        "command_line": None,
        "children": []
    },
    '038e3fd4b9d5a183bbe6382607fd4d24bc396d519aacb32e91caeb4f4af75c87': {
        "image": '?sys32\\net.exe|?sys32\\taskhostw.exe|?win\\explorer.exe',
        "command_line": None,
        "children": []
    },
    'e6668b64d08edebb273525a1dba5c9b984d8d219d5da4a2109f8c1fb62f6d86f': {
        "image": '?sys32\\net.exe|?sys32\\taskhostw.exe|?sys32\\net.exe',
        "command_line": None,
        "children": []
    },
    '440ce82d152195f945e8230ee313a275dc7c1833da63b5a8b059763f6eda624d': {
        "image": '?sys32\\net.exe|?sys32\\taskhostw.exe|system',
        "command_line": None,
        "children": []
    },
    '47dedb344240a9c0508372c8218c6c53e742f2aee0fe07fad8f76dfb6c67730a': {
        "image": '?sys32\\lsass.exe|?sys32\\net.exe|?sys32\\svchost.exe',
        "command_line": None,
        "children": []
    },
    '17fca5cfde9e73939fa33977a72231a88d3933e488b15b3817910b9188cd25f4': {
        "image": '?usr\\appdata\\local\\programs\\python\\python310-32\\pythonw.exe',
        "command_line": None,
        "children": []
    },
    'ef6cf296627416a69dadbc347c7b1a52296a2f51c3ad7750dcf53de368a4b0b2': {
        "image": '?sys32\\conhost.exe|?sys32\\wevtutil.exe|?sys32\\conhost.exe',
        "command_line": None,
        "children": []
    },
    'bab5cb464f970fcadb5f46b9554f1a2142d23811960e9d1b46e36b043571075c': {
        "image": '?sys32\\lsass.exe|?win\\pyw.exe',
        "command_line": None,
        "children": []
    },
    '4b575bc41667cc714447b7121e2f4a163915e565d02793a5988e4a354f46d74a': {
        "image": '?sys32\\net.exe|?sys32\\lsass.exe|?sys32\\net.exe',
        "command_line": None,
        "children": []
    },
    '0bdb827669bfae348b5b984888148bca0f4fc26fee4dba262f4b84e10bfca0e0': {
        "image": '?sys32\\net.exe|?sys32\\lsass.exe|?sys32\\dwm.exe',
        "command_line": None,
        "children": []
    },
    'fd37eaa39260f8052a567f8c449799b8362e15ebdc68db7b18beeeb5abdc3da6': {
        "image": '?sys32\\net.exe|?sys32\\lsass.exe|system',
        "command_line": None,
        "children": []
    },
    'a27e31d0e25fae7c489b1b34d0d52357e34e76e9133f840e97c88ab77f00ba6d': {
        "image": '?sys32\\net.exe|?sys32\\lsass.exe|?win\\explorer.exe',
        "command_line": None,
        "children": []
    },
    'd5280faf227e83c39f7677e26b5bdadf8cb1fe0a60b98e81eeabd76716c02562': {
        "image": '?sys32\\net.exe|?sys32\\lsass.exe|?usr\\appdata\\local\\programs\\python\\python310-32\\pythonw.exe',
        "command_line": None,
        "children": []
    },
    'b152d4568d35951e91e80d2cedce144dcc4714962da66c0abfdab397e31bbbbe': {
        "image": '?sys32\\svchost.exe|?sys32\\rundll32.exe',
        "command_line": None,
        "children": []
    },
    '7b554f89b82cc500e3d30bce6d21905c477c5584dff653c29aefc3d6dff7ef56': {
        "image": '?sys32\\usoclient.exe',
        "command_line": None,
        "children": []
    },
    '15ab311950199c8f6f57dda0afa319b5dc0a26c2b889dc9775b5b2023a04ce55': {
        "image": '?sys32\\net.exe',
        "command_line": None,
        "children": []
    },
    '94a5f5f7967fa4ff12f7d70cb76779385fbd3fc32ebed1583101cbe82a7691dc': {
        "image": '?sys32\\sgrmbroker.exe',
        "command_line": None,
        "children": []
    },
    '17a5e7b851aed02b16665f240c7d5fb2259c62d534e3ca5a5847c76d9d51cb57': {
        "image": '?sys32\\mousocoreworker.exe',
        "command_line": None,
        "children": []
    },
    'bb0efe6793884094938f2df541d1b614f18969679ebb181e8124bf665241b75b': {
        "image": '?sys32\\cmd.exe|?sys32\\conhost.exe',
        "command_line": None,
        "children": []
    },
    '833315d9ffa1b1188e89ee2eae51a1c3720a4501d7a5ab9fdc9801902a0f6502': {
        "image": '?sys32\\net.exe|?sys32\\net1.exe',
        "command_line": 'C:\\Windows\\system32\\net1 stop winmgmt /y',
        "children": []
    },
    '612562b4bade644efa0fd184731d01a1d9bb89f3fd5f0ee64e814626fc2d56d2': {
        "image": '?sys32\\services.exe|?sys32\\taskhost.exe',
        "command_line": None,
        "children": []
    },
    '977836ec776aa8e541046a5047dbbcf07dfe0927ecb505792a653111e0309ad6': {
        "image": '?sys32\\services.exe|?sys32\\sc.exe',
        "command_line": 'C:\\Windows\\system32\\sc.exe start w32time task_started',
        "children": []
    },
    '99adabfe8e0f84fb13a54944584fc85042aa71dd649c79f7bd42977507c28050': {
        "image": '?sys32\\calc.exe',
        "command_line": 'C:\\Windows\\SysWOW64\\calc.exe',
        "children": []
    }
}
