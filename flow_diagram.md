
## En diagrama de flujo

+-------------------+
|  Evento Logstash  |
|  Contiene los campos |
|  client_mac       |
|  service_provider_uuid |
+-------------------+
          |
          v
+---------------------------+
|  Verifica scrambles cache |
|  (Memcached)              |
+---------------------------+
          |
          v
+---------------------------+
|  Existe scramble para     |
|  este sp_uuid?            |
+---------------------------+
     |           |
   No|           |Sí
     v           v
  [Salta]    +------------------------+
             |  Obtiene:              |
             |  - mac_hashing_salt    |
             |  - mac_prefix          |
             +------------------------+
                        |
                        v
             +------------------------+
             |  Construye la key:     |
             |  key = prefix + MAC    |
             |  (sin ":")             |
             +------------------------+
                        |
                        v
             +------------------------+
             |  Aplica PBKDF2 HMAC    |
             |  SHA1 con:             |
             |  - key                  |
             |  - salt                 |
             |  - 10 iteraciones       |
             |  - 6 bytes salida       |
             +------------------------+
                        |
                        v
             +------------------------+
             |  Convierte bytes a HEX  |
             |  y reconstruye formato |
             |  xx:xx:xx:xx:xx:xx     |
             +------------------------+
                        |
                        v
             +------------------------+
             |  Reemplaza client_mac  |
             |  en el evento          |
             +------------------------+
                        |
                        v
             +------------------------+
             | Evento modificado listo|
             +------------------------+
