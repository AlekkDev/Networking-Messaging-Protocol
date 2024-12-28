| **Field**      | **Size (bytes)** | **Description**                                                                                                                                 |
|-----------------|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| **Type**       | 1                | Specifies the type of datagram. Possible values:                                                                                                |
|                 |                  | - `0x01`: Control datagram                                                                                                                     |
|                 |                  | - `0x02`: Chat datagram                                                                                                                        |
| **Operation**  | 1                | Indicates the operation type. Possible values:                                                                                                 |
|                 |                  | - If `Type == 0x01` (Control datagram):                                                                                                        |
|                 |                  |   - `0x01`: ERR (Error condition occurred)                                                                                                     |
|                 |                  |   - `0x02`: SYN (Used in sliding window algorithm)                                                                                             |
|                 |                  |   - `0x04`: ACK (Acknowledgment for sliding window algorithm or general acknowledgement)                                                       |
|                 |                  |   - `0x08`: FIN (Connection closure)                                                                                                           |
|                 |                  | - If `Type == 0x02` (Chat datagram): Operation always equals `0x01`.                                                                           |
| **Sequence**   | 1                | Sequence number used to identify resent or lost datagrams. Possible values: `0x00` or `0x01`.                                                  |
| **User**       | 32               | User name encoded as an ASCII string.                                                                                                          |
| **Length**     | 4                | Specifies the length of the datagram payload in bytes.                                                                                         |
| **Payload**    | Variable         | Contains data based on the `Type` field:                                                                                                       |
|                 |                  | - If `Type == 0x01` (Control datagram) and `Operation == 0x01` (ERR): A human-readable error message as an ASCII string.                       |
|                 |                  | - If `Type == 0x02` (Chat datagram): The contents of the chat message to be sent.                                                              |
