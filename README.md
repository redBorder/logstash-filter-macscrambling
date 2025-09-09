# Summary

## Entrada

Se presupone la presencian de los campos:
- client_mac
- service_provider_uuid

## Salida

- El valor de client_mac es sustituido

# Qué hace este filtro:

Para cada evento que tenga **client_mac** y **service_provider_uuid**:

1. Busca el **scramble** correspondiente en **Memcached**.
2. Si existe un mac_hashing_salt, genera una MAC ofuscada usando PBKDF2 + prefijo.
3. Reemplaza la **client_mac** original en el evento por la ofuscada.
4. Actualiza los scrambles desde Memcached automáticamente cada **update_rate** segundos.

## En diagrama de flujo (GPT made)

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


# Propósito:

Protege los logs para que las MAC no sean rastreables desde diferentes dominios pero mantienen unicidad relativa para indentificar cuantitativamente los eventos a través de la MAC.

# Ejemplo de uso:

``` conf
filter {
  macscrambling {
    memcached_server => "memcached.service"
  }
}
```