<h3>Перенос настроек DHCP с одного узла на другой</h3>

Программа предназначена для переноса настроек DHCP с одного UTM на другой.

Перенос возможен на устройства UserGate версий 5 и 6 на другое устройсво UserGate версий 5 и 6 в любой комбинации версий.<br>

В процессе работы программы создаётся файл в формате json с конфигурацией DHCP subnets.
Можно экспортировать конфигурцию, затем внести необходимые изменения.
Затем импортировать изменённый файл конфигурации.

Программа работает в UTM версии 5 и версии 6.

Работает в Linux и Windows.<br>
Для Linux запускать в терминале.

Запрашивает ip узла, login и пароль исходного узла и узла назначения.

Для работы программы На интерфейсе UTM необходимо включить сервис xml-rpc.
1. Открыть веб-консоль администратора таким образом: https://<usergate_ip>:8001/?features=zone-xml-rpc
2. В настройках нужной зоны активировать сервис "XML-RPC для управления".

Файл для Linux: <b>ug_dhcp_subnet</b> (Перед использованием сделать исполняемым.)<br>
Файл для Windows: <b>ug_dhcp_subnet.exe</b>
