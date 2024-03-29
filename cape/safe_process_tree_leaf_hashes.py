# These are the stock default process tree ids that are safelist in CAPE
# Of the format <processtree_id>: <tree_id_hash>
SAFE_PROCESS_TREE_LEAF_HASHES = {
    "-": "3973e022e93220f9212c18d0d0c543ae7c309e46640da93a4a0314de999f5112",
    "/opt/microsoft/omsagent/ruby/bin/ruby": "efbb6ee6d739f6fa409b15920ac221ad99798bee806b45c39c796a250146392d",
    "/opt/sysmon/sysmon": "d098cab10a58f19f65662ff02d5292b6cff701c714138124d997fff0841f13d5",
    "/usr/bin/dash|/opt/omi/bin/omicli": "86129e5a947758e7b49cb839d7e5a23a5fe57a9d69d2cc8e81c7163577d1f74c",
    "/usr/bin/dash|/usr/bin/grep": "d79b03312b88795c8d09fdc0d01c9c8700a04a73e71704f8608cfb3191514ca6",
    "/usr/bin/dash|/usr/bin/sudo|/opt/microsoft/omsagent/ruby/bin/ruby": "1aab034f0907b4d29ceae8d8b40d23acf6316705c7df0251ea1b72d0034a58bf",
    "/usr/bin/df": "b3eb40f639bf7e4e63c16a216aadb486f00ab3cb5a6e7c9de19ed9b411d0766e",
    "/usr/bin/pgrep": "e6dbe312ef0f83b6abe0e064e47102e61a96c134c0d83fed9fc35992741c0bc1",
    "<unknown process>": "4eda24bcfaeff701f29cb02ab4630f81d8831ebadd777aaf663841e7facd3c76",
    "?c\\python27\\pythonw.exe": "49a2ab6c73a10ee6bd97a0ba200c6f6dc0dc2977059b8029579e780748f19c72",
    "?pf86\\common files\\microsoft shared\\officesoftwareprotectionplatform\\osppsvc.exe": "f405c23c52c0dd0cd7ac31f92df0e76f9c6702b155ca5be6afbc076bb81d82a6",
    "?pf86\\microsoft\\edge\\application\\106.0.1370.47\\bho\\ie_to_edge_stub.exe": "7a569f652c1711967a935feedac0a2bf196c3bd5a7e8f75f85f02c65fe48e188",
    "?pf86\\microsoft\\edge\\application\\106.0.1370.47\\identity_helper.exe": "524241b8a3e1a062d8edf4058545fbd5c7300068c9c3cdffd4ea81c008553c99",
    "?pf86\\microsoft\\edge\\application\\111.0.1661.62\\bho\\ie_to_edge_stub.exe": "803ad39e1d0684a5f9ea5735405459055f5b811c030e71c24d13be9afe38ec69",
    "?pf86\\microsoft\\edge\\application\\111.0.1661.62\\identity_helper.exe": "938e63d8cf31fbae53d4c71670d24b35a422befc7243fed8338e056514b459f5",
    "?pf86\\microsoft\\edge\\application\\msedge.exe": "666cb65f44287de82e3b77628abd670990c78732e42ef209b4baaf6e5fe8bace",
    "?pf86\\microsoft\\edge\\application\\msedge.exe|?pf86\\microsoft\\edge\\application\\msedge.exe": "c7e4b5c4b3a1ae3fefaf965b87233e02beeb961c43e3844165979c69f199980d",
    "?pf86\\microsoft\\edgeupdate\\microsoftedgeupdate.exe": "be60898adbbbb25571447e166b7dc47774caa0c08a25b58c702265d9493dd8cf",
    "?pf86\\windowsapps\\microsoft.windows.photos_2022.30070.26007.0_x64__8wekyb3d8bbwe\\microsoft.photos.exe": "1b4a01c9672bc7575a1be176490f1e46b52bbfb88c5267a4b6c3d6b5c1ff3a95",
    "?pf86\\windowsapps\\microsoft.windowscalculator_11.2210.0.0_x64__8wekyb3d8bbwe\\calculatorapp.exe": "662c95994a54c1974ce7f2724f75cc225c42a90ab0d65a9beea497260b2ce363",
    "?pf86\\windowsapps\\microsoft.windowscommunicationsapps_16005.13426.20920.0_x64__8wekyb3d8bbwe\\hxtsr.exe": "a53afad8f3925d95edace69eb6e68184b3d52bdaae0bacdd2f7df5ede70446a8",
    "?pf86\\windowsapps\\microsoft.windowscommunicationsapps_16005.14326.21374.0_x64__8wekyb3d8bbwe\\hxtsr.exe": "40de00bfbbc177376235b1f93097ce3f1cd89aafdffe18f016a2862b6e443267",
    "?pf86\\windowsapps\\microsoft.xboxgamingoverlay_5.621.4222.0_x64__8wekyb3d8bbwe\\gamebar.exe": "bcb1213942dd880cc729f5b6cad820e1cc0c0c92cdd4ab3e3919edd6e40fbb64",
    "?pf86\\windowsapps\\microsoft.xboxgamingoverlay_5.621.4222.0_x64__8wekyb3d8bbwe\\gamebarftserver.exe": "fd4fad363ee4c67ab9826cff5ab63d8a68bde96c63b60d70bc7654d26695e469",
    "?sys32\\applicationframehost.exe": "cb8cf6824c4b649db886611e67de6506bae4d4f5b36f92969f95479b02abefc1",
    "?sys32\\backgroundtaskhost.exe": "01bf5d0579b4db52ee0322f9f84b7db238c037a2d32b4969298830612ffbdcf8",
    "?sys32\\backgroundtaskhost.exe|?sys32\\conhost.exe": "73eb56621fbdbdfaeb669105ba4eb327854790d55994a23a2f852fed8bf9b9af",
    "?sys32\\backgroundtransferhost.exe": "f3de6d0a84196f1af3fe985f772c7a4dd23a7979286e78c9928d3f3fcb090a82",
    "?sys32\\calc.exe": "99adabfe8e0f84fb13a54944584fc85042aa71dd649c79f7bd42977507c28050",
    "?sys32\\cmd.exe|?sys32\\conhost.exe": "bb0efe6793884094938f2df541d1b614f18969679ebb181e8124bf665241b75b",
    "?sys32\\conhost.exe": "51b9684487d1a103549ec6f5773e058932073037dc30fdb6580c9c388503cf74",
    "?sys32\\conhost.exe|?sys32\\cmd.exe": "476af2541f60045ea6fb29913f65e83ad506e0377a9ddfaf200683ed0ed0457d",
    "?sys32\\conhost.exe|?sys32\\net.exe": "c59c9356f5b4fe145261f2537853cf3d3e40bda7d687642d502d8a7804b1996b",
    "?sys32\\conhost.exe|?sys32\\net.exe|?sys32\\conhost.exe": "e1867cb5da2934113ecb1cc3bd153cdda3bc011508ec481cea7ca65ef026f6e5",
    "?sys32\\conhost.exe|?sys32\\net1.exe": "f907b893fb58d829ea064101eaea311fc3b349f4df57d98585d2a1e9947db152",
    "?sys32\\conhost.exe|?sys32\\sc.exe": "994e09b156ed0844663bfce7510a7473ca574523c874ff47f3ed99f7d096f249",
    "?sys32\\conhost.exe|?sys32\\wevtutil.exe": "d347dce729508445a629ec5824e89745a78ad5ca4ac5e438a435f5991b40c8cc",
    "?sys32\\conhost.exe|?sys32\\wevtutil.exe|?sys32\\conhost.exe": "5a30b8b7b2840fca2e94ebb7170fc993cd3171f5901339d9a6dd02470c1279de",
    "?sys32\\ctfmon.exe": "aa43ef5d5f78c7017d4ba1ad33b988ca68e2a2635f5010d8c0bc8157816770c2",
    "?sys32\\dinotify.exe": "6fa48cc6d3ecd1c0f3a16aaa38a3a623da5340b78b0319839d3bd5952357a967",
    "?sys32\\dllhost.exe": "d1c20b94425d2d866bdd30adc1af7d7ce5b08c30c7418f618d8164ac06ae76ee",
    "?sys32\\lsass.exe": "d3b14a95c2160abc76f356b5e9b79c71c91035e49f1c5962ce7a100e61decd78",
    "?sys32\\lsass.exe|?sys32\\net.exe|?sys32\\svchost.exe": "c664a60e7d5c76f89b61c325cce9cc4b946a99451a18934873d15238a8d4a62c",
    "?sys32\\lsass.exe|?sys32\\services.exe": "47830026ec6e7934e9bee21c86b764197b3113b9aa14de58a85eb99bf8f95625",
    "?sys32\\lsass.exe|?sys32\\services.exe|?pf86\\common files\\microsoft shared\\officesoftwareprotectionplatform\\osppsvc.exe": "652b12a35e5d88c4d20603b264c81f5bfc4c2eb840f8f8f4542aa4843a26743b",
    "?sys32\\lsass.exe|?win\\pyw.exe": "d11777b614f7efad7ab6b7e06732556403790aebb52e147f6b43c1256b41e8f6",
    "?sys32\\mobsync.exe": "6a27c89bdbe4f9855307c59f8c8a480e9a76681cf533d18690754baa250228db",
    "?sys32\\mousocoreworker.exe": "17a5e7b851aed02b16665f240c7d5fb2259c62d534e3ca5a5847c76d9d51cb57",
    "?sys32\\musnotifyicon.exe": "b12bbea6f1a504c7288762f649b849457edbee81b4967863dad67f3158b250fb",
    "?sys32\\net.exe": "15ab311950199c8f6f57dda0afa319b5dc0a26c2b889dc9775b5b2023a04ce55",
    "?sys32\\net.exe|?sys32\\conhost.exe": "cc02ea74d37fa271b43948cbe04647261f44090145b68b536d455252e9320e45",
    "?sys32\\net.exe|?sys32\\lsass.exe|?sys32\\dwm.exe": "584540d66850ca079014a1b3189c0aacaa33aaf8a68cfe4fe09c9339d72d9d26",
    "?sys32\\net.exe|?sys32\\lsass.exe|?sys32\\net.exe": "9082d9de901d315e11aa1bbe278eb56fdb6578dda51ddc6eec526cd3473a0fe0",
    "?sys32\\net.exe|?sys32\\lsass.exe|?usr\\appdata\\local\\programs\\python\\python310-32\\pythonw.exe": "f0c0d2c0f62330c002d47334326c66bf956ba7999416feae5fa7075092d86fb6",
    "?sys32\\net.exe|?sys32\\lsass.exe|?win\\explorer.exe": "e43ed8415ee4a6880abe244d065f80ce155045594f7f89d2b978e9eff9c85feb",
    "?sys32\\net.exe|?sys32\\lsass.exe|system": "555c81bd4cbab205aafe8a297a3e77532f77abb8ea2cbc90a5acbeee2070547b",
    "?sys32\\net.exe|?sys32\\net1.exe": "833315d9ffa1b1188e89ee2eae51a1c3720a4501d7a5ab9fdc9801902a0f6502",
    "?sys32\\net.exe|?sys32\\taskhostw.exe|?pf86\\microsoft\\edgeupdate\\microsoftedgeupdate.exe": "b637b53ac15a5e02cbed2ae2a2c84abe65431bbd4a98c65f49021367adbe7e79",
    "?sys32\\net.exe|?sys32\\taskhostw.exe|?sys32\\conhost.exe": "6a63433f0d81e1327147b039e3b09e4e7433a5c7bbd06993265d4371a0788408",
    "?sys32\\net.exe|?sys32\\taskhostw.exe|?sys32\\net.exe": "51e005a90d571ee0da2a38d16ddde377dc0578931ecf384d1b199e9b520179e2",
    "?sys32\\net.exe|?sys32\\taskhostw.exe|?sys32\\runtimebroker.exe": "2a1189dfe5f6c90b69e0c6f0993f3399e69bf8c8042b3b17849a9752b0192453",
    "?sys32\\net.exe|?sys32\\taskhostw.exe|?usr\\appdata\\local\\programs\\python\\python310-32\\pythonw.exe": "5d504d769a67bb605df9297808402b721626e656055e442496b85bb12846e80f",
    "?sys32\\net.exe|?sys32\\taskhostw.exe|?win\\explorer.exe": "4c0bc34edca5e4dce2ef032797bfa5af8aa6c3147786ee415d27592f772220e3",
    "?sys32\\net.exe|?sys32\\taskhostw.exe|?win\\pyw.exe": "120dd5e7b29c912a0117751a0239caccff7d58f44c23be2ca38f9afeff1d0902",
    "?sys32\\net.exe|?sys32\\taskhostw.exe|?win\\systemapps\\microsoft.windows.search_cw5n1h2txyewy\\searchapp.exe": "a0bb42bb923b33d6775fcc61ec62e9c538fafd933c19228237131e07dd387ac9",
    "?sys32\\net.exe|?sys32\\taskhostw.exe|?win\\systemapps\\microsoft.windows.startmenuexperiencehost_cw5n1h2txyewy\\startmenuexperiencehost.exe": "db2eee18cf26bf58fbb888a1ed86a03321b367d9bb5abfb2ab5d4ddd180a6f75",
    "?sys32\\net.exe|?sys32\\taskhostw.exe|system": "9cf3e1d49e57b3938584aab3685b0ab39588434bdabf5eeda944a07455135990",
    "?sys32\\net1.exe": "72f73ead06808f10feb9f2fa35900fc8ca7ac1759a8928544251b33a0a6a9056",
    "?sys32\\remotefxvgpudisablement.exe": "2ae01e5403fb56f97aace63b3b309cc88cb8906602a60dece33058bbe327d156",
    "?sys32\\runtimebroker.exe": "1fc2ec278dbd4f03d4a6ea748d35f75b554e43b8211fc5bcebb2ff295e03182b",
    "?sys32\\sc.exe": "50c958b80515a739a7a9397890d310a91d1e3593ab1aae7757331d71768ccc4a",
    "?sys32\\sc.exe|?sys32\\conhost.exe": "ab2bf0e9666652ed8254b079209e27568e0e55a4418cfe94a48181f34625ff15",
    "?sys32\\sc.exe|?sys32\\conhost.exe|?sys32\\wermgr.exe": "54e726d55dcb6c6c4914a0ae899d89c454442624fa64c824bee9110b4abc7721",
    "?sys32\\sdclt.exe": "faac8a70045bd7596a1f1e368e346130e357b6f5e8b043287653dfe1fabb12b9",
    "?sys32\\searchfilterhost.exe": "a54f2146bd3272b89f7b9c7047f2b436a9514f89feeed754bcc6d19d32dc2db3",
    "?sys32\\searchindexer.exe": "acbf70b95a96ba178eb89269e7f1db5f622fa4b6b009cd29284d7be14024625b",
    "?sys32\\searchprotocolhost.exe": "49d9994a34643bea4cc71a26501d1e58ccabd051a1cf9704184b6374e1ef3764",
    "?sys32\\services.exe|?sys32\\sc.exe": "977836ec776aa8e541046a5047dbbcf07dfe0927ecb505792a653111e0309ad6",
    "?sys32\\services.exe|?sys32\\svchost.exe": "f26db097862af031c8a7ab84423f063be7f6e01f50699cdd3bfc23542af6a5b4",
    "?sys32\\services.exe|?sys32\\taskhost.exe": "612562b4bade644efa0fd184731d01a1d9bb89f3fd5f0ee64e814626fc2d56d2",
    "?sys32\\sgrmbroker.exe": "94a5f5f7967fa4ff12f7d70cb76779385fbd3fc32ebed1583101cbe82a7691dc",
    "?sys32\\slui.exe": "b04893383338161ca8bec608cb9b877acf5c6708cbc4244ec5d0f49f5ab4b9f1",
    "?sys32\\smss.exe": "44e862ebd67cd7ffe848064c41aa16111ec0d95c918bb792d1625df1d98b29aa",
    "?sys32\\sppextcomobj.exe": "2a119d477c12829140fb54e41c8666a0a8a37aa8f71f41a61746e6b7c144d70a",
    "?sys32\\sppsvc.exe": "7e2c38006c7720d214b726be34bf3bbfca1c8f02c3b36f7c8b7c7198f119c8a2",
    "?sys32\\svchost.exe": "f3d6ed01b460589fbebaf89c2fcad5503bf4d86993fb20d410eace46a595108f",
    "?sys32\\svchost.exe|?c\\python27\\pythonw.exe": "78f84277f3383d654d64679ea93be5614d09b588006f0e9ca7395bb797a6f942",
    "?sys32\\svchost.exe|?pf86\\microsoft\\edgeupdate\\microsoftedgeupdate.exe": "683045c417897765931f9c4de5799babaf16b2ab34a6a3a30eb442512c7df6cf",
    "?sys32\\svchost.exe|?pf86\\windowsapps\\microsoft.yourphone_1.22022.180.0_x64__8wekyb3d8bbwe\\yourphone.exe": "34f75b36eb062dd4e2fceecea864aeb679d15099f6b76d46d9e881cdc0c2565f",
    "?sys32\\svchost.exe|?sys32\\conhost.exe": "5f4653a82121522720fbb9bdab186d70bf7f21e1ca475cb87b12f448ea71e1ca",
    "?sys32\\svchost.exe|?sys32\\dwm.exe": "f2917a808064123e3affa565e9bcbe222ed377a586291c5db0c253647c094d44",
    "?sys32\\svchost.exe|?sys32\\fontdrvhost.exe": "31c722814723945f3a75457cc44353b4d3569c6a352af85dccafa182c58ad653",
    "?sys32\\svchost.exe|?sys32\\mqsvc.exe": "9c1ab7458090e539853fc3467a646f6609bfd65562c493123a0a0bbbf8010756",
    "?sys32\\svchost.exe|?sys32\\rundll32.exe": "b152d4568d35951e91e80d2cedce144dcc4714962da66c0abfdab397e31bbbbe",
    "?sys32\\svchost.exe|?sys32\\searchfilterhost.exe": "1851240177eab8d1db9cae2a230ba8f46f660b99de4324457bfad2b51346bef5",
    "?sys32\\svchost.exe|?sys32\\searchprotocolhost.exe": "444f02be8905f4dc7be2ab190159644baebab2bd8ed351ceb6474ce317440f0c",
    "?sys32\\svchost.exe|?sys32\\sihost.exe": "eae18f81f6dd53ad84a780d67f1f91c6f8427e2aba53aeb3617e2c6a64ca6731",
    "?sys32\\svchost.exe|?sys32\\svchost.exe": "da60beb532bc62cd2208910c086bcbabc4488d45e2dcc4e8414b3969e7902fc7",
    "?sys32\\svchost.exe|?sys32\\taskhost.exe": "8c173d9b81725561674d18ec4e7c77d21f93b19384b342fbdf1592f5fc6300f3",
    "?sys32\\svchost.exe|?sys32\\wbem\\wmiprvse.exe": "ca2681bddeb1b3c58f48ab9244d677808317cc73efb553bf6376621456696386",
    "?sys32\\svchost.exe|?sys32\\werfault.exe": "2f6044eb59e4d5104cfd7025ffd14fe2bea9405c566f7f4ecc9548f694fad00a",
    "?sys32\\svchost.exe|?win\\explorer.exe": "1d038671bb56576c62a176c7902e6867a978732d1ecafe792c8ac6ac3dde79ba",
    "?sys32\\svchost.exe|?win\\microsoft.net\\framework64\\v4.0.30319\\smsvchost.exe": "d5eaaf0f58b9480f6d77d6f8cc07fc7de6f0100fd9cb20ffffcd4e3755ac2c91",
    "?sys32\\svchost.exe|?win\\systemapps\\microsoftwindows.client.cbs_cw5n1h2txyewy\\inputapp\\textinputhost.exe": "04184d24f08dadab15c91374f7aedba484d8214d0d3c2e8b240e3b7b6f25d959",
    "?sys32\\taskhost.exe": "d922fb8a674c43236b96805a7ba2d4090f0cb7e6ae12d0186339c9ad489c6386",
    "?sys32\\taskhostw.exe|?sys32\\dwm.exe": "260f245517682394cfaf63bd7ad3d8030eaed6a401ba06cb90ac6ea5f243d6d5",
    "?sys32\\taskhostw.exe|?sys32\\fontdrvhost.exe": "4b58dcf63cbc4670d86b768a8ca61f5b1eb6ad75cfadfcc2a0aa2ced8b356c4c",
    "?sys32\\taskhostw.exe|?sys32\\mqsvc.exe": "bd903b69112691f4b9c235bb38ddd0dff5f05c01ff8c5f8a696c8323c2def921",
    "?sys32\\taskhostw.exe|?sys32\\sihost.exe": "9f9d7a40460f0f79354bb1762cf191be23e240e82f49a8bf93d1663d03559bd5",
    "?sys32\\taskhostw.exe|?sys32\\spoolsv.exe": "3a9ac55c7601867575c13e6b01be19fc4cc9089d2ef099849b5cf65900b178d4",
    "?sys32\\taskhostw.exe|?sys32\\taskhostw.exe": "7cc9a34571b93f606903926f4f1278aeaf9832bff1e32347daa66ba168299b52",
    "?sys32\\taskhostw.exe|?sys32\\upfc.exe": "f9d864dd2d14d8823a3f3d567954242399d5fbd4c23c069383385428c31585f0",
    "?sys32\\taskhostw.exe|?sys32\\wininit.exe": "4abbc5c36ce3748761bc91485c54ca4e3cd661a3806a45cc646bdf89fc762b8d",
    "?sys32\\taskhostw.exe|?sys32\\winlogon.exe": "cfe46e2bf4895376c14e20303452fbde40e2340e4632447babc55b444cb270f3",
    "?sys32\\taskhostw.exe|memcompression": "677403b425b332c6eed9a5a5dae1a02da50a873cb333ad664666d2b4168b2342",
    "?sys32\\taskhostw.exe|registry": "b6c58e6bc7947b19761a1c60b241703e895efb37b48cd42c94bb1965dcf92777",
    "?sys32\\userinit.exe": "6dea6b390c3611c05f7ce0a8d56b136431168161237ae254f4f0a3eeedb52fa9",
    "?sys32\\usoclient.exe": "7b554f89b82cc500e3d30bce6d21905c477c5584dff653c29aefc3d6dff7ef56",
    "?sys32\\waasmedicagent.exe": "25a026bdd54385f3aaefb8e1723f5be97b7c36e255b2c48f7f7f8a66d9df7eb8",
    "?sys32\\wbem\\wmiadap.exe": "24954e76154b030985354403bdb85d0a334c0007c842f5381ed8a0544f11466b",
    "?sys32\\wbem\\wmiprvse.exe": "9c58c41fb2916bea2d6059e912a55c5505ce0b3b7b78cdf6ee3321387ce0f0ae",
    "?sys32\\werfault.exe": "0e3b8b7c5bbffdf8923f5acd914194d7f5db897b73a0f0541dc13750e4af718a",
    "?sys32\\wermgr.exe": "2dd065baf9009515b0d68a64a7cf324ff325893fb8ca630febed2950a3be7432",
    "?sys32\\wevtutil.exe": "5a5f1f8bf9b80413fff222a0a88c3c52c018f9539f0904590999d46c75df012b",
    "?sys32\\wevtutil.exe|?sys32\\conhost.exe": "ef6cf296627416a69dadbc347c7b1a52296a2f51c3ad7750dcf53de368a4b0b2",
    "?sys32\\winlogon.exe|?sys32\\wlrmdr.exe": "d6b00a6a4585b9a9e4f410d713037c8f570ef3c1e7adf8aca2f0f79b186b66d8",
    "?sys32\\wlrmdr.exe": "e1d55007ec820d344a9f4c752bb18d1b096fc3372c515c40a43ac1f2229e95b3",
    "?usr\\appdata\\local\\programs\\python\\python310-32\\pythonw.exe": "17fca5cfde9e73939fa33977a72231a88d3933e488b15b3817910b9188cd25f4",
    "?usr\\appdata\\local\\programs\\python\\python38-32\\pythonw.exe": "7ebc8a21cfcc0374fdb80a24a23b21e568ffb58285782b115cde8315f58b3c58",
    "?win\\explorer.exe|?sys32\\werfault.exe": "a7756c96db89aaf251d32633e40b57c104807060c3f7c650c0b94ea90cb0458b",
    "?win\\microsoft.net\\framework64\\v4.0.30319\\mscorsvw.exe": "fe1b33fe682a3ce734f5e66aface2e59bad7a91741a6166b793e1658a44cab7b",
    "?win\\microsoft.net\\framework\\v4.0.30319\\mscorsvw.exe": "eea8165b1ac8e04a4257e249753f1b8085e712521e3fc44718a49bb94851ff1b",
    "?win\\systemapps\\microsoft.windows.search_cw5n1h2txyewy\\searchapp.exe": "44dcdb8d08f7fdcfe0843d73a652ddbe1e1729fdfdcb66e8f009d3f82a3103ea",
    "?win\\systemapps\\microsoft.windows.startmenuexperiencehost_cw5n1h2txyewy\\startmenuexperiencehost.exe": "aa5dd26518bf22e0d6ca76b67a2295934aa52858ec19b47affadf99cbd328a2e",
    "?win\\systemapps\\microsoftwindows.client.cbs_cw5n1h2txyewy\\inputapp\\textinputhost.exe": "e7a3087aba99f3aa0dd4aa5a44d0be58256b4ef41be49da617026838f5204f5c",
    "<unknown process>": "4eda24bcfaeff701f29cb02ab4630f81d8831ebadd777aaf663841e7facd3c76",
    "system": "bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073",
}
