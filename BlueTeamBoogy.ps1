

$blue_app_list = @("sysmon64.exe", 
                   "winlogbeat.exe", 
                   "velociraptor.exe", 
                   "filebeat.bat", 
                   "elasticsearch.exe", 
                   "logstash.bat", 
                   "osquery.exe", 
                   "suricata.exe");

$malicious_app_list = @("rootkitx64.exe", 
                        "maldrive.exe", 
                        "b0tctrl.exe", 
                        "spy4u.exe", 
                        "killdisk.exe",
                        "ratty.exe",
                        ".mlwre.exe",
                        ".thorse32.exe",
                        "payloader.exe",
                        "hackkit.exe",
                        "linkin-park-tried_so_hard.mp3.exe",
                        "limewire.exe",
                        "james_webb_space_img.png.exe",
                        "limewire.exe","utorrent.exe");

$crash_reason_list = @("incorrect configuration",
                        "insufficient privileges",
                        "invalid license",
                        "invalid install folder",
                        "missing package files",
                        "unrecognized encoding",
                        "unsupported filesystem",
                        "invalid arguments",
                        "corrupt files",
                        "i/o error");

$user_name_list = @("Administrator",
                    "Guest",
                    "PC",
                    "ServiceAccount",
                    "LocalUser",
                    "User01",
                    "WindowsUser",
                    "LocalAdmin",
                    "Piotr",
                    "Dmitri");

$document_name_list = @("'Cooking recepies.pdf'",
                        "'How to setup an ELK.docx'",
                        "'IKEA - assembling a rug.pdf'",
                        "'tinder - Cheat sheet'",
                        "'How To Reverse An Invasion.docx'",
                        "'UNO game rules.pdf'",
                        "'Systembolaget Oppettider.pdf'",
                        "'Blockchains - how i think it work.docx'",
                        "'How to remove french locale config.pdf'",
                        "'Elastic vs Splunk vs Excel.pdf'",
                        "'Why is there even a printer in this network.lol'");

$port_list = @("1234",
               "4444",
               "5066",
               "53598",
               "6354",
               "9092",
               "3999",
               "2409",
               "4200",
               "54222",
               "5555");

$external_device_list = @("Kingston 2T SSD",
                          "SanDisk 32GB USB",
                          "Razor gaming mouse",
                          "USB vacuum",
                          "Commodore 64");

$driver_file_list = @("file.sys",
                      "HP_JetsmartDriver.drv",
                      "HPPrinterDrivers.inf",
                      "HPsNonHarmfulDriver.ime",
                      "InnocentDrivers.sys",
                      "MouserDrivers.drv",
                      "vacuum_cleaner_drivers.sys");


$application_log_sources = $(Get-EventLog -LogName Application |Select-Object Source -Unique | foreach { $_.Source });

$event_list = @("308", "1000", "1102", "1116", "1117", "2003", "4624", "4625", "4688","4720","4722", "6416", "7045", "11707", "11708", "20001");
$event_hashmap = @{ "308" = @($user_name_list, @("printed the document"), $document_name_list, "Information", "SecurityCenter");                                                  
                    "1000" = @($blue_app_list, @("crashed due to"), $crash_reason_list, "Error", "Application Error");                                                            
                    "1102" = @($user_name_list, @("cleared the"), @("audit log"), "Warning", "SecurityCenter");                                                                   
                    "1116" = @(@("Windows Defender detected a malware"), @(" - "), $malicious_app_list, "Warning","SecurityCenter");                                              
                    "1117" = @(@("Windows Defender successfully stopped and removed a detected malware"), @(" - "), $blue_app_list, "Information","SecurityCenter");              
                    "2003" = @(@("The firewall has been configured to allow incoming"), @("TCP traffic on port", "UDP traffic on port"), $port_list, "Warning","SecurityCenter"); 
                    "4624" = @($user_name_list, @("successfully"), @("signed in"), "Information", "SecurityCenter");                                                             
                    "4625" = @($user_name_list, @("unsuccessfully"), @("signed in"), "Warning", "SecurityCenter");                                                           
                    "4688" = @(@("A new process"), @("was started by"), $malicious_app_list, "Information", "SecurityCenter");                                               
                    "4720" = @(@("The user account"), $user_name_list, @("was created"), "Information", "SecurityCenter");                                                   
                    "4722" = @(@("The user account"), $user_name_list, @("was enabled"), "Information", "SecurityCenter");                                                   
                    "6416" = @($external_device_list, @("was connected"), @("to the machine"), "Information", "SecurityCenter");                                             
                    "7045" = @($malicious_app_list, @("was installed"), @("as a service"), "Information", "Application Management");                                         
                    "11707" = @($malicious_app_list, @("was successfully"), @("installed"), "Information", "SecurityCenter");                                                
                    "11708" = @($blue_app_list, @("was unsuccessfully"), @("installed"), "Error", "Application Error");                                                      
                    "20001" = @(@("The driver"), $driver_file_list, @("were successfully installed"), "Information", "SecurityCenter"); };                                   


while($true){
    $iterate_times = $(Get-Random -Minimum 200 -Maximum 350);
    $cooldown = $(Get-Random -Minimum 1 -Maximum 2);

    for ($i=0; $i -le $iterate_times; $i+=1 ){
        $event = $(Get-Random $event_list);
        $message1 = $(Get-Random $event_hashmap[$event][0]);
        $message2 = $(Get-Random $event_hashmap[$event][1]);
        $message3 = $(Get-Random $event_hashmap[$event][2]);
        $entry_type = $event_hashmap[$event][3];
        $log_source = $event_hashmap[$event][4];

    
        if ([System.Diagnostics.EventLog]::SourceExists($log_source)){
            Write-EventLog -EventId $event -LogName Application -Message "$message1 $message2 $message3" -Source $log_source -EntryType $entry_type -RawData 10,20 ;
        }else{
            Write-EventLog -EventId $event -LogName Application -Message "$message1 $message2 $message3" -Source "Application Error" -EntryType $entry_type -RawData 10,20 ;
        }
    }
    Start-Sleep -Seconds $cooldown;
}