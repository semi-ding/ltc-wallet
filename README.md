# ltc-wallet (V1 ready)
Spring Boot based 2-of-3 multisig wallet implementation for LTC.  If you find any problem, please open an issue. or you can contact sam@acrosafe.io.

## Testnet
TestNet4 will be used in default and dev branch. Both Q and M addresses are supported.

If you want a stable test environment, **set up your own node**, LitecoinJ lib will automatically connect to localhost first.

**TestNet4Params.java** is provided in etc folder. feel free to use it.

## Setup Development Environment
1. Install PostgreSQL and Java 8.
2. Create a new role. user name is "wallet", password is "password". Set the privileges to yes for all.
3. Create a new DB, name is "ltcWallet", set the owner to the newly created role.
4. Run ltc-wallet-1.0.0-SNAPSHOT.jar by using "java -jar ltc-wallet-1.0.0-SNAPSHOT.jar", If you want to run it on LTC mainnet, please use prod profile.
5. Copy the checkpoint file in etc folder to <user_home> folder if you want to accelarate the blockchain download speed.
6. When you see "All blocks have been downloaded. LTC wallet service is available." in your log, you system has started. It takes less than one minute if you use checkpoint. hours if not.

Note: If you have problem about ltc-core.jar in the pom, please add it to your maven repo manually.

## REST API 
- **List all transactions:  GET** https://hostname:9300/api/v1/ltc/wallet/{walletId}/transaction/all?pageId=0&size=100

  example output:
  
  ```javascript
  {
      "size": 9,
      "transactions": [
        {
          "transactionId": "66eb672c9abddd2fbcca761108fe3da9988102dd646b0ea0bbc92f976124ef8f",
          "status": "confirmed",
          "fee_string": "0",
          "created_date": "2020-02-29T16:18:48.755753Z",
          "wallet_id": "36c156efe2774effb9dfaf9dc966d89e",
          "transaction_type": "DEPOSIT",
          "outputs": [
            {
              "amount_string": "0.02",
              "amount_in_smallest_unit_string": "2000000",
              "receive_address": "2N3aGFWk2K8PHx7KwBe53Fb8kXBgjjUc4cH",
              "index": 1
            }
          ]
        },
        {
          "transactionId": "41f3cebdd096e3422f0e479a7aca6837176bfec93b148911a84f5446d3046c80",
          "status": "confirmed",
          "fee_string": "0",
          "created_date": "2020-02-29T16:18:48.959347Z",
          "wallet_id": "36c156efe2774effb9dfaf9dc966d89e",
          "transaction_type": "DEPOSIT",
          "outputs": [
            {
              "amount_string": "0.03",
              "amount_in_smallest_unit_string": "3000000",
              "receive_address": "2MwyJiUC88pGKEGdPYnZZPKSZ6siKNQCXk9",
              "index": 1
            }
          ]
        },
        {
          "transactionId": "757cdefc74239937498378fdd306531f0806542205b687281b5f9ff75fe0b096",
          "status": "confirmed",
          "fee_string": "0",
          "created_date": "2020-02-29T22:47:38.383282Z",
          "wallet_id": "36c156efe2774effb9dfaf9dc966d89e",
          "transaction_type": "WITHDRAWAL",
          "outputs": [
            {
              "amount_string": "0.01772574",
              "amount_in_smallest_unit_string": "1772574",
              "receive_address": "2NFvJTVC1gTczFsH5WmfH88THhjDKD1r9VX",
              "index": 0
            }
          ]
        },
        {
          "transactionId": "ae9aa64c88a93a87eb676e84c41f4aa0af377a3c656cf40f19adaa175d9521eb",
          "status": "unconfirmed",
          "fee_string": "0",
          "created_date": "2020-03-01T13:31:46.508370Z",
          "wallet_id": "36c156efe2774effb9dfaf9dc966d89e",
          "transaction_type": "WITHDRAWAL",
          "outputs": [
            {
              "amount_string": "0.01198111",
              "amount_in_smallest_unit_string": "1198111",
              "receive_address": "tb1qcfxn0t3htlufzq6xe5cgcl3g2r2590vpp64had",
              "index": 1
            },
            {
              "amount_string": "0.01188111",
              "amount_in_smallest_unit_string": "1188111",
              "receive_address": "2MzwkogEL5bQ2bGqfEtXtmQjB6PW6T79fhw",
              "index": 2
            }
          ]
        }
      ]
  }
  ```


- **Create wallet:  POST** https://hostname:9300/api/v1/ltc/wallet/new

    wallet-per-user is supported. You can create one or multiple wallets for one user. Based on our performance test, each microservice should be able to support 200 wallet.
  
  example input:
  ```javascript
  {
  	"symbol": "LTC",
  	"label":"test wallet 001",
  	"signing_key_passphrase":"abcdefg",
  	"backup_signing_key_passphrase":"abcdefg",
  	"enabled":true
  }
  ```
  
  example output:
  ```javascript
  {
    "id": "36c156efe2774effb9dfaf9dc966d89e",
    "enabled": true,
    "created_date": "2020-02-29T15:07:39.438267300Z",
    "encrypted_signing_key": "asbqxN1NPydktlq35IIoDkUZlGRZlZtpSPewIfEqPnKwVNcQfNphPExBvWgUW8WZ",
    "encrypted_backup_key": "RjSPVy6NQzu49umyuq3IQrS8N5eEfrjMh3ArEzbVHS8BaEPVrTttUo8p96Lo1JLB",
    "iv_spec": "ap6uVFj9QPfXH3NQhK1zFA==",
    "salt": "+6D9ZdJpgBwja6b37CCr6Q==",
    "seed_creation_time": 1582988859
  }
  ```

  
- **Get wallet:  GET**  https://hostname:9300/api/v1/ltc/wallet/{walletId}

    output example:
    ```javascript
    {
      "id": "36c156efe2774effb9dfaf9dc966d89e",
      "enabled": true,
      "createdDate": "2020-02-29T15:07:39.438267Z",
      "label": "test wallet 001",
      "balance": {
        "estimated": "0.15157122",
        "available": "0.15157122"
      }
    }
    ```
    
- **List wallets:  GET**  https://hostname:9300/api/v1/ltc/wallet/all?pageId=0&size=10

    output example:
    
    ```javascript
    {
      "wallets": [
        {
          "id": "7aaa9fcb5fad4764a0e394f9ad4c35c4",
          "enabled": true,
          "createdDate": "2020-03-01T16:25:07.567015Z",
          "label": "test wallet 001",
          "balance": {
            "estimated": "0",
            "available": "0"
          }
        },
        {
          "id": "5f81982cefca4e308db13f43f96aebea",
          "enabled": true,
          "createdDate": "2020-03-01T16:25:06.466924Z",
          "label": "test wallet 001",
          "balance": {
            "estimated": "0",
            "available": "0"
          }
        },
        {
          "id": "d78a8b2fe3824732bdaecdc16c32f561",
          "enabled": true,
          "createdDate": "2020-03-01T16:25:04.957556Z",
          "label": "test wallet 001",
          "balance": {
            "estimated": "0",
            "available": "0"
          }
        },
        {
          "id": "36c156efe2774effb9dfaf9dc966d89e",
          "enabled": true,
          "createdDate": "2020-02-29T15:07:39.438267Z",
          "label": "test wallet 001",
          "balance": {
            "estimated": "0.15157122",
            "available": "0.15157122"
          }
        },
        {
          "id": "71e7f9ccaa0d4dbabd762c3808f64da0",
          "enabled": true,
          "createdDate": "2020-02-29T04:51:19.171487Z",
          "label": "test wallet 001",
          "balance": {
            "estimated": "0",
            "available": "0"
          }
        }
      ]
    }
    ```

- **Generate receiving address:  POST**   https://hostname:9300/api/v1/ltc/wallet/{walletId}/address/new

    example input:
    ```javascript
  {
  	"symbol":"LTC",
    "label": "testing"
  }
  ```
  
  example output:
  ```javascript
  {
    "address": "QgXBSfzMed9yeRc7pntu4hkoo1b2seQxFD",
    "label": "user1asdfasdfasf"
  }
  ```

- **Get Balance:  GET**   https://hostname:9300/api/v1/ltc/wallet/{walletId}}/balance

    example output:
    ```javascript
    {
      "id": "36c156efe2774effb9dfaf9dc966d89e",
      "balance": {
        "estimated": "0.17545148",
        "available": "0.17545148"
      }
    }
    ```

- **Send coin directly:   POST**   https://hostname:9300/api/v1/ltc/wallet/{walletId}/send

   example input:
    
   ```javascript
      {
       "symbol":"LTC",
       "internal_id": "alskjdflaksdlfk",
       "number_block":6,
       "signing_key_passphrase":"abcdefg",
       "using_backup_signer":false,
       "recipients":
       [
       	{
       		"address":"QiHk1ma1VzqyeK7aDsh6YWvGiX35HAFViE",
       		"amount":"1133110"
       	},
       	{
       		"address":"Qi3RnHucANAFtCrMBLT2xNVoAVqcSQkjEW",
       		"amount":"1122110"
       	}
       ]
       }
   ```
     
   example output:
   
   ```javascript
      {
        {
          "transaction_id": "ae9aa64c88a93a87eb676e84c41f4aa0af377a3c656cf40f19adaa175d9521eb"
        }
      }
   ```
- **Sign Transaction:   POST**   https://hostname:9300/api/v1/ltc/wallet/{walletId}/sign

    example input:
    ```javascript
          {
           "symbol":"lTC",
           "internal_id": "alskjdflaksdlfk",
           "number_of_block":6,
           "signing_key_passphrase":"abcdefg",
           "using_backup_signer":false,
           "recipients":
           [
           	  {
           		"address":"QiHk1ma1VzqyeK7aDsh6YWvGiX35HAFViE",
           		"amount":"1133110000000"
           	  },
           	  {
           		"address":"Qi3RnHucANAFtCrMBLT2xNVoAVqcSQkjEW",
           		"amount":"1133110000000"
           	  }
           ]
           }
    ```
          
    example output:
          
    ```javascript
          {
            "fee_in_string": "0.00001804",
            "transaction_hex": "0100000001eb393c1f9ea9a516b5c3e77c33839c66e82e4d1271decba5d2baa7f30fd8b71001000000fc0047304402205548ddd4b60b4a5bcd8dc0f55c80fc51ed15e301fe40219acddf01e141c9b3fb022072383faf7395a9fde8514f8b0809a78369ac98724b5d4d59ab8adc727d7fb63701473044022078e3ca7a204e513b78b3041fa143cf313d490fa4f5dc3b5384242e8046f707b6022067cafc27b082bf7e5133d2a1134b45809717a287889c895f2db871862e89770f014c69522102198b151d36179bd87a740e198b0122d10088f497a0ffec418154510ed880c0e2210262491149733e1950da219c64ad1a67044ce418f209d90cdefd48cb10af0b0a752103e2490c98cdcf29c5967d177f50261f86d6c128118b7ce3b09e49dac8f53e730353aeffffffff03462674000000000017a9146e00f3c8bc3ef01618988ffb047621db2b43f028871f48120000000000160014c24d37ae375ff8910346cd308c7e2850d542bd810f2112000000000017a91454733e69914609b27e84af7e8ffe6aff46106ab78700000000",
            "number_blocks": 6
          }
    ```
          
- **Broadcast Transaction:  POST**   https://hostname:9300/api/v1/ltc/wallet/{walletId}/broadcast

    example input:
           
    ```javascript
       {
            "transaction_hex":"0100000001eb393c1f9ea9a516b5c3e77c33839c66e82e4d1271decba5d2baa7f30fd8b71001000000fc0047304402205548ddd4b60b4a5bcd8dc0f55c80fc51ed15e301fe40219acddf01e141c9b3fb022072383faf7395a9fde8514f8b0809a78369ac98724b5d4d59ab8adc727d7fb63701473044022078e3ca7a204e513b78b3041fa143cf313d490fa4f5dc3b5384242e8046f707b6022067cafc27b082bf7e5133d2a1134b45809717a287889c895f2db871862e89770f014c69522102198b151d36179bd87a740e198b0122d10088f497a0ffec418154510ed880c0e2210262491149733e1950da219c64ad1a67044ce418f209d90cdefd48cb10af0b0a752103e2490c98cdcf29c5967d177f50261f86d6c128118b7ce3b09e49dac8f53e730353aeffffffff03462674000000000017a9146e00f3c8bc3ef01618988ffb047621db2b43f028871f48120000000000160014c24d37ae375ff8910346cd308c7e2850d542bd810f2112000000000017a91454733e69914609b27e84af7e8ffe6aff46106ab78700000000",
            "transaction_memo": "1234567890"
       }
    ```
            
    example output:
          
    ```javascript
        {
            "transaction_id": "ae9aa64c88a93a87eb676e84c41f4aa0af377a3c656cf40f19adaa175d9521eb"
        }
    ```

