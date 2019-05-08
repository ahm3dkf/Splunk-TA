

while(true)
do

echo "[*] copying the 99-splunk file to /etc/security/limits.d/ "
cp /tmp/99-splunk.conf /etc/security/limits.d/
ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in copying the file /tmp/99-splunk.conf TO /etc/security/limits.d/"
break;
fi
echo "[*] Successfully completed"


echo "[*] copying the disable_thp.service file to /etc/systemd/system/ "

cp /tmp/disable_thp.service /etc/systemd/system/

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in copying the file /tmp/disable_thp.service TO /etc/systemd/system/"
break;
fi
echo "[*] Successfully completed"


echo "[*] doing command : systemctl daemon-reload "
systemctl daemon-reload

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in command : systemctl daemon-reload "
break;
fi
echo "[*] Successfully completed"

echo "[*] doing command : systemctl enable disable_thp.service"

systemctl enable disable_thp.service

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in command : systemctl enable disable_thp.service "
break;
fi
echo "[*] Successfully completed"

echo "[*] doing command : systemctl start disable_thp.service"
systemctl start disable_thp.service

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in command : systemctl start disable_thp.service "
break;
fi
echo "[*] Successfully completed"

echo "[*] doing command : systemctl start disable_thp.service"

systemctl start disable_thp.service


ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in command : systemctl start disable_thp.service "
break;
fi
echo "[*] Successfully completed"

echo "[*] doing command : sed \"s/SELINUX=enforcing/SELINUX=disabled/g\" -i /etc/sysconfig/selinux "

sed "s/SELINUX=enforcing/SELINUX=disabled/g" -i /etc/sysconfig/selinux
sed "s/SELINUX=enforcing/SELINUX=disabled/g" -i /etc/selinux/config

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in command : sed \"s/SELINUX=enforcing/SELINUX=disabled/g\" -i /etc/sysconfig/selinux "
break;
fi
echo "[*] Successfully completed"


service firewalld start

echo "[*] doing command : firewall-cmd --add-port=8000/tcp --permanent"

firewall-cmd --add-port=8000/tcp --permanent

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in command : firewall-cmd --add-port=8000/tcp --permanent "
break;
fi
echo "[*] Successfully completed"

echo "[*] doing command : firewall-cmd --add-port=8089/tcp --permanent "

firewall-cmd --add-port=8089/tcp --permanent

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in command : firewall-cmd --add-port=8089/tcp --permanent "
break;
fi
echo "[*] Successfully completed"

echo "[*] doing command :firewall-cmd --add-port=9997/tcp --permanent"

firewall-cmd --add-port=9997/tcp --permanent

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in command : firewall-cmd --add-port=9997/tcp --permanent "
break;
fi
echo "[*] Successfully completed"

echo "[*] doing command : service firewalld restart"

service firewalld restart

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in command : service firewalld restart "
break;
fi
echo "[*] Successfully completed"

cd /tmp/



echo "[*] installing wget : yum install wget -yy "

yum install wget -yy

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in yum install wget -yy "
break;
fi
echo "[*] Successfully completed"


echo "[*] downloading splunk "

wget -O splunk-7.2.5.1-962d9a8e1586-Linux-x86_64.tgz 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=7.2.5.1&product=splunk&filename=splunk-7.2.5.1-962d9a8e1586-Linux-x86_64.tgz&wget=true'

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in downloading splunk "
break;
fi
echo "[*] Successfully completed"

echo "[*] doing command : tar zxf splunk-7.2.5.1-962d9a8e1586-Linux-x86_64.tgz"

tar zxf splunk-7.2.5.1-962d9a8e1586-Linux-x86_64.tgz

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in command : tar zxf splunk-7.2.5.1-962d9a8e1586-Linux-x86_64.tgz "
break;
fi
echo "[*] Successfully completed"

echo "[*] doing command : cp /tmp/splunk -r /opt/"

cp /tmp/splunk -r /opt/

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in command : cp splunk -r /opt/ "
break;
fi

echo "[*] Successfully completed"


echo "[*] doing command : useradd splunk"

useradd splunk

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in command : useradd splunk "
break;
fi
echo "[*] Successfully completed"

echo "[*] doing command : chown -R splunk: /opt/splunk/ "


chown -R splunk: /opt/splunk/

ret_code=$?
if [ $ret_code != 0 ]; 
then 
echo "error in command : chown -R splunk: /opt/splunk/ "
break;
fi
echo "[*] Successfully completed"

echo "you must reboot the server "

break
done

