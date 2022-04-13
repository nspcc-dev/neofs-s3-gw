# AWS CLI basic usage

## Configuration

### Credentials

To configure basic settings that the AWS CLI uses to interact with the Gateway, follow the steps below:

1. issue a secret with neofs-authmate tool (see [NeoFS Authmate] (#neofs-authmate))
2. execute the command
```
$ aws configure
```
after you enter this command, the AWS CLI will prompt you for four pieces of information, like in this example
(replace with your own values):
```
AWS Access Key ID [None]: 5g933dyLEkXbbAspouhPPTiyLZRg4axBW1axSPD87eVT0AiXsH4AjYy1iTJ4C1WExzjBrSobJsQFWEyKLREe5sQYM
AWS Secret Access Key [None]: 438bbd8243060e1e1c9dd4821756914a6e872ce29bf203b68f81b140ac91231c
Default region name [None]: ru 
Default output format [none]: json 
```

## Basic usage

> **_NOTE:_** To specify the IP and the port of the gate, append `--endpoint-url https://%IP:%PORT` to your commands.

### Bucket

#### Obtainment of a list of buckets 

To view the list of the buckets in the NeoFS node, to which the gateway is connected, enter the following command:
```
$ aws s3 ls 
```

#### Creation of a bucket

At this moment, the gateway supports only canned ACL and doesn't support the setting of location constraints.

To create a bucket, run the following command:
```
$ aws s3api create-bucket --bucket %BUCKET_NAME --acl %ACL
```
where `%ACL` can be represented by a hex encoded value or by keywords `public-read-write`, `private`, `public-read`. 
If the parameter is not set, the default value is `private`.

#### Deletion of a bucket 

To delete a bucket, execute the following command:
```
$ aws s3api delete-bucket --bucket %BUCKET_NAME
```

### Object

#### Obtainment of a list of objects

To view the list of the objects in a bucket, run:
```
$ aws s3api list-objects --bucket %BUCKET_NAME 
```

#### Upload of a file

To upload a file into a bucket in the NeoFS network, run the following command:
```
$ aws s3api put-object --bucket %BUCKET_NAME --key %OBJECT_KEY --body  %FILEPATH
```
where %OBJECT_KEY is the filename of an object in NeoFS

#### Upload of a dir

To upload a dir into a bucket in the NeoFS network, run the following command:

```
$ aws s3 sync %DIRPATH s3://%BUCKET_NAME 
```

#### Download of a file

To download a file from a bucket in the NeoFS Network, execute:
```
$ aws s3api get-object --bucket  %BUCKET_NAME --key %OBJECT_KEY %OUTFILE
```

where %OUTFILE is the file to store object content.

#### Deletion of a file
To delete a file:
```
$ aws s3api delete-object --bucket %BUCKET_NAME --key %FILE_NAME
```
