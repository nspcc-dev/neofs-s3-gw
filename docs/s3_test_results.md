# S3 compatibility test results

To update this file using tests result run:
```sh
./updateTestsResult.sh ceph_tests_result.txt
```

## CopyObject

Compatibility: 14/17/17

|    | Test                                                                      | s3-gw | aws s3 |
|----|---------------------------------------------------------------------------|-------|--------|
| 1  | s3tests_boto3.functional.test_s3.test_copy_object_ifmatch_good            | ok    | ok     |
| 2  | s3tests_boto3.functional.test_s3.test_copy_object_ifmatch_failed          | ok    | ok     |
| 3  | s3tests_boto3.functional.test_s3.test_copy_object_ifnonematch_good        | ok    | ok     |
| 4  | s3tests_boto3.functional.test_s3.test_copy_object_ifnonematch_failed      | ok    | ok     |
| 5  | s3tests_boto3.functional.test_s3.test_object_copy_zero_size               | ok    | ok     |
| 6  | s3tests_boto3.functional.test_s3.test_object_copy_same_bucket             | ok    | ok     |
| 7  | s3tests_boto3.functional.test_s3.test_object_copy_verify_contenttype      | ok    | ok     |
| 8  | s3tests_boto3.functional.test_s3.test_object_copy_to_itself               | ok    | ok     |
| 9  | s3tests_boto3.functional.test_s3.test_object_copy_to_itself_with_metadata | ERROR | ok     |
| 10 | s3tests_boto3.functional.test_s3.test_object_copy_diff_bucket             | ok    | ok     |
| 11 | s3tests_boto3.functional.test_s3.test_object_copy_not_owned_bucket        | ERROR | ok     |
| 12 | s3tests_boto3.functional.test_s3.test_object_copy_not_owned_object_bucket | ERROR | ok     |
| 13 | s3tests_boto3.functional.test_s3.test_object_copy_canned_acl              | ok    | ok     |
| 14 | s3tests_boto3.functional.test_s3.test_object_copy_retaining_metadata      | ok    | ok     |
| 15 | s3tests_boto3.functional.test_s3.test_object_copy_replacing_metadata      | ok    | ok     |
| 16 | s3tests_boto3.functional.test_s3.test_object_copy_bucket_not_found        | ok    | ok     |
| 17 | s3tests_boto3.functional.test_s3.test_object_copy_key_not_found           | ok    | ok     |

## GetObject

Compatibility: 27/29/33

|    | Test                                                                                     | s3-gw | aws s3 |
|----|------------------------------------------------------------------------------------------|-------|--------|
| 1  | s3tests_boto3.functional.test_s3.test_get_object_ifmatch_good                            | ok    | ok     |
| 2  | s3tests_boto3.functional.test_s3.test_get_object_ifmatch_failed                          | ok    | ok     |
| 3  | s3tests_boto3.functional.test_s3.test_get_object_ifnonematch_good                        | ok    | ok     |
| 4  | s3tests_boto3.functional.test_s3.test_get_object_ifnonematch_failed                      | ok    | ok     |
| 5  | s3tests_boto3.functional.test_s3.test_get_object_ifmodifiedsince_good                    | ok    | ok     |
| 6  | s3tests_boto3.functional.test_s3.test_get_object_ifmodifiedsince_failed                  | ok    | ok     |
| 7  | s3tests_boto3.functional.test_s3.test_get_object_ifunmodifiedsince_good                  | ok    | ok     |
| 8  | s3tests_boto3.functional.test_s3.test_get_object_ifunmodifiedsince_failed                | ok    | ok     |
| 9  | s3tests_boto3.functional.test_s3.test_object_read_not_exist                              | ok    | ok     |
| 10 | s3tests_boto3.functional.test_s3.test_object_requestid_matches_header_on_error           | ok    | ok     |
| 11 | s3tests_boto3.functional.test_s3.test_object_head_zero_bytes                             | ok    | ok     |
| 12 | s3tests_boto3.functional.test_s3.test_object_read_unreadable                             | FAIL  | FAIL   |
| 13 | s3tests_boto3.functional.test_s3.test_ranged_request_response_code                       | ok    | ok     |
| 14 | s3tests_boto3.functional.test_s3.test_ranged_big_request_response_code                   | ok    | ok     |
| 15 | s3tests_boto3.functional.test_s3.test_ranged_request_skip_leading_bytes_response_code    | ok    | ok     |
| 16 | s3tests_boto3.functional.test_s3.test_ranged_request_return_trailing_bytes_response_code | ok    | ok     |
| 17 | s3tests_boto3.functional.test_s3.test_ranged_request_invalid_range                       | ok    | ok     |
| 18 | s3tests_boto3.functional.test_s3.test_ranged_request_empty_object                        | ok    | ok     |
| 19 | s3tests_boto3.functional.test_s3.test_atomic_read_1mb                                    | ok    | ok     |
| 20 | s3tests_boto3.functional.test_s3.test_atomic_read_4mb                                    | ok    | ok     |
| 21 | s3tests_boto3.functional.test_s3.test_atomic_read_8mb                                    | ok    | ok     |
| 22 | s3tests_boto3.functional.test_s3.test_object_raw_get_x_amz_expires_not_expired           | ERROR | ok     |
| 23 | s3tests_boto3.functional.test_s3.test_object_raw_get_x_amz_expires_out_range_zero        | ok    | ok     |
| 24 | s3tests_boto3.functional.test_s3.test_object_raw_get_x_amz_expires_out_max_range         | ok    | FAIL   |
| 25 | s3tests_boto3.functional.test_s3.test_object_raw_get_x_amz_expires_out_positive_range    | ok    | FAIL   |
| 26 | s3tests_boto3.functional.test_s3.test_object_raw_get                                     | ok    | ok     |
| 27 | s3tests_boto3.functional.test_s3.test_object_raw_get_bucket_gone                         | ok    | ok     |
| 28 | s3tests_boto3.functional.test_s3.test_object_delete_key_bucket_gone                      | ERROR | ok     |
| 29 | s3tests_boto3.functional.test_s3.test_object_header_acl_grants                           | ERROR | ERROR  |
| 30 | s3tests_boto3.functional.test_s3.test_object_raw_get_object_gone                         | ok    | ok     |
| 31 | s3tests_boto3.functional.test_s3.test_object_raw_get_object_acl                          | ERROR | ok     |
| 32 | s3tests_boto3.functional.test_s3.test_object_raw_authenticated                           | ok    | ok     |
| 33 | s3tests_boto3.functional.test_s3.test_object_raw_response_headers                        | ERROR | ok     |

## PutObject

Compatibility: 17/37/64

|    | Test                                                                                           | s3-gw       | aws s3 |
|----|------------------------------------------------------------------------------------------------|-------------|--------|
| 1  | s3tests_boto3.functional.test_s3.test_put_object_ifmatch_good                                  | ERROR       | ERROR  |
| 2  | s3tests_boto3.functional.test_s3.test_put_object_ifmatch_failed                                | FAIL        | FAIL   |
| 3  | s3tests_boto3.functional.test_s3.test_put_object_ifmatch_overwrite_existed_good                | ERROR       | ERROR  |
| 4  | s3tests_boto3.functional.test_s3.test_put_object_ifmatch_nonexisted_failed                     | FAIL        | FAIL   |
| 5  | s3tests_boto3.functional.test_s3.test_put_object_ifnonmatch_good                               | ERROR       | ERROR  |
| 6  | s3tests_boto3.functional.test_s3.test_put_object_ifnonmatch_failed                             | ERROR       | FAIL   |
| 7  | s3tests_boto3.functional.test_s3.test_put_object_ifnonmatch_nonexisted_good                    | ERROR       | ERROR  |
| 8  | s3tests_boto3.functional.test_s3.test_put_object_ifnonmatch_overwrite_existed_failed           | ERROR       | FAIL   |
| 9  | s3tests_boto3.functional.test_headers.test_object_create_bad_md5_invalid_short                 | UNSUPPORTED | ok     |
| 10 | s3tests_boto3.functional.test_headers.test_object_create_bad_md5_bad                           | UNSUPPORTED | ok     |
| 11 | s3tests_boto3.functional.test_headers.test_object_create_bad_md5_empty                         | UNSUPPORTED | ok     |
| 12 | s3tests_boto3.functional.test_headers.test_object_create_bad_md5_none                          | ok          | ok     |
| 13 | s3tests_boto3.functional.test_headers.test_object_create_bad_expect_mismatch                   | ERROR       | ok     |
| 14 | s3tests_boto3.functional.test_headers.test_object_create_bad_expect_empty                      | ok          | ok     |
| 15 | s3tests_boto3.functional.test_headers.test_object_create_bad_expect_none                       | ok          | ok     |
| 16 | s3tests_boto3.functional.test_headers.test_object_create_bad_contentlength_empty               | FAIL        | ok     |
| 17 | s3tests_boto3.functional.test_headers.test_object_create_bad_contentlength_negative            | ok          | ok     |
| 18 | s3tests_boto3.functional.test_headers.test_object_create_bad_contentlength_none                | FAIL        | FAIL   |
| 19 | s3tests_boto3.functional.test_headers.test_object_create_bad_contentlength_mismatch_above      | ERROR       | ERROR  |
| 20 | s3tests_boto3.functional.test_headers.test_object_create_bad_contenttype_invalid               | ok          | ok     |
| 21 | s3tests_boto3.functional.test_headers.test_object_create_bad_contenttype_empty                 | ok          | ok     |
| 22 | s3tests_boto3.functional.test_headers.test_object_create_bad_contenttype_none                  | ok          | ok     |
| 23 | s3tests_boto3.functional.test_headers.test_object_create_bad_authorization_empty               | FAIL        | FAIL   |
| 24 | s3tests_boto3.functional.test_headers.test_object_create_date_and_amz_date                     | ERROR       | ERROR  |
| 25 | s3tests_boto3.functional.test_headers.test_object_create_amz_date_and_no_date                  | ERROR       | ERROR  |
| 26 | s3tests_boto3.functional.test_headers.test_object_create_bad_authorization_none                | FAIL        | FAIL   |
| 27 | s3tests_boto3.functional.test_headers.test_object_create_bad_md5_invalid_garbage_aws2          | UNSUPPORTED | ok     |
| 28 | s3tests_boto3.functional.test_headers.test_object_create_bad_contentlength_mismatch_below_aws2 | FAIL        | ok     |
| 29 | s3tests_boto3.functional.test_headers.test_object_create_bad_authorization_incorrect_aws2      | FAIL        | FAIL   |
| 30 | s3tests_boto3.functional.test_headers.test_object_create_bad_authorization_invalid_aws2        | FAIL        | FAIL   |
| 31 | s3tests_boto3.functional.test_headers.test_object_create_bad_ua_empty_aws2                     | ERROR       | ok     |
| 32 | s3tests_boto3.functional.test_headers.test_object_create_bad_ua_none_aws2                      | ERROR       | ok     |
| 33 | s3tests_boto3.functional.test_headers.test_object_create_bad_date_invalid_aws2                 | FAIL        | ok     |
| 34 | s3tests_boto3.functional.test_headers.test_object_create_bad_date_empty_aws2                   | FAIL        | ok     |
| 35 | s3tests_boto3.functional.test_headers.test_object_create_bad_date_none_aws2                    | FAIL        | FAIL   |
| 36 | s3tests_boto3.functional.test_headers.test_object_create_bad_date_before_today_aws2            | FAIL        | ok     |
| 37 | s3tests_boto3.functional.test_headers.test_object_create_bad_date_before_epoch_aws2            | FAIL        | ok     |
| 38 | s3tests_boto3.functional.test_headers.test_object_create_bad_date_after_end_aws2               | FAIL        | ok     |
| 39 | s3tests_boto3.functional.test_s3.test_object_anon_put                                          | ERROR       | ok     |
| 40 | s3tests_boto3.functional.test_s3.test_object_put_authenticated                                 | ERROR       | ok     |
| 41 | s3tests_boto3.functional.test_s3.test_object_raw_put_authenticated_expired                     | ERROR       | FAIL   |
| 42 | s3tests_boto3.functional.test_s3.test_object_write_file                                        | ok          | ok     |
| 43 | s3tests_boto3.functional.test_s3.test_object_write_check_etag                                  | FAIL        | ok     |
| 44 | s3tests_boto3.functional.test_s3.test_object_write_cache_control                               | ERROR       | ok     |
| 45 | s3tests_boto3.functional.test_s3.test_object_write_expires                                     | ERROR       | ok     |
| 46 | s3tests_boto3.functional.test_s3.test_object_write_read_update_read_delete                     | ERROR       | ok     |
| 47 | s3tests_boto3.functional.test_s3.test_object_set_get_metadata_none_to_good                     | ok          | ok     |
| 48 | s3tests_boto3.functional.test_s3.test_object_set_get_metadata_none_to_empty                    | ERROR       | ok     |
| 49 | s3tests_boto3.functional.test_s3.test_object_set_get_metadata_overwrite_to_empty               | ERROR       | ok     |
| 50 | s3tests_boto3.functional.test_s3.test_object_set_get_non_utf8_metadata                         | ok          | FAIL   |
| 51 | s3tests_boto3.functional.test_s3.test_object_set_get_metadata_empty_to_unreadable_prefix       | ok          | FAIL   |
| 52 | s3tests_boto3.functional.test_s3.test_object_set_get_metadata_empty_to_unreadable_suffix       | ok          | FAIL   |
| 53 | s3tests_boto3.functional.test_s3.test_object_set_get_metadata_empty_to_unreadable_infix        | ok          | FAIL   |
| 54 | s3tests_boto3.functional.test_s3.test_object_metadata_replaced_on_put                          | ERROR       | ok     |
| 55 | s3tests_boto3.functional.test_s3.test_object_write_to_nonexist_bucket                          | ok          | ok     |
| 56 | s3tests_boto3.functional.test_s3.test_atomic_write_1mb                                         | ok          | ok     |
| 57 | s3tests_boto3.functional.test_s3.test_atomic_write_4mb                                         | ok          | ok     |
| 58 | s3tests_boto3.functional.test_s3.test_atomic_write_8mb                                         | ok          | ok     |
| 59 | s3tests_boto3.functional.test_s3.test_atomic_dual_write_1mb                                    | ERROR       | ERROR  |
| 60 | s3tests_boto3.functional.test_s3.test_atomic_dual_write_4mb                                    | ERROR       | ERROR  |
| 61 | s3tests_boto3.functional.test_s3.test_atomic_dual_write_8mb                                    | ERROR       | ERROR  |
| 62 | s3tests_boto3.functional.test_s3.test_atomic_conditional_write_1mb                             | ERROR       | ERROR  |
| 63 | s3tests_boto3.functional.test_s3.test_atomic_dual_conditional_write_1mb                        | ERROR       | FAIL   |
| 64 | s3tests_boto3.functional.test_s3.test_atomic_write_bucket_gone                                 | ERROR       | ok     |

## PostObject

Compatibility: 0/32/33

|     | Test                                                                                     | s3-gw | aws s3 |
|-----|------------------------------------------------------------------------------------------|-------|--------|
| 1   | s3tests_boto3.functional.test_s3.test_post_object_anonymous_request                      | FAIL  | ok     |
| 2   | s3tests_boto3.functional.test_s3.test_post_object_authenticated_request                  | FAIL  | ok     |
| 3   | s3tests_boto3.functional.test_s3.test_post_object_authenticated_no_content_type          | FAIL  | ok     |
| 4   | s3tests_boto3.functional.test_s3.test_post_object_authenticated_request_bad_access_key   | FAIL  | ok     |
| 5   | s3tests_boto3.functional.test_s3.test_post_object_set_success_code                       | FAIL  | ok     |
| 6   | s3tests_boto3.functional.test_s3.test_post_object_set_invalid_success_code               | FAIL  | ok     |
| 7   | s3tests_boto3.functional.test_s3.test_post_object_upload_larger_than_chunk               | FAIL  | ok     |
| 8   | s3tests_boto3.functional.test_s3.test_post_object_set_key_from_filename                  | FAIL  | ok     |
| 9   | s3tests_boto3.functional.test_s3.test_post_object_ignored_header                         | FAIL  | ok     |
| 10  | s3tests_boto3.functional.test_s3.test_post_object_case_insensitive_condition_fields      | FAIL  | ok     |
| 11  | s3tests_boto3.functional.test_s3.test_post_object_escaped_field_values                   | FAIL  | ok     |
| 12  | s3tests_boto3.functional.test_s3.test_post_object_success_redirect_action                | FAIL  | ok     |
| 13  | s3tests_boto3.functional.test_s3.test_post_object_invalid_signature                      | FAIL  | ok     |
| 14  | s3tests_boto3.functional.test_s3.test_post_object_invalid_access_key                     | FAIL  | ok     |
| 15  | s3tests_boto3.functional.test_s3.test_post_object_invalid_date_format                    | FAIL  | ok     |
| 16  | s3tests_boto3.functional.test_s3.test_post_object_no_key_specified                       | FAIL  | ok     |
| 17  | s3tests_boto3.functional.test_s3.test_post_object_missing_signature                      | FAIL  | ok     |
| 18  | s3tests_boto3.functional.test_s3.test_post_object_missing_policy_condition               | FAIL  | ok     |
| 19  | s3tests_boto3.functional.test_s3.test_post_object_user_specified_header                  | FAIL  | ok     |
| 20  | s3tests_boto3.functional.test_s3.test_post_object_request_missing_policy_specified_field | FAIL  | ok     |
| 21  | s3tests_boto3.functional.test_s3.test_post_object_condition_is_case_sensitive            | FAIL  | ok     |
| 22  | s3tests_boto3.functional.test_s3.test_post_object_expires_is_case_sensitive              | FAIL  | ok     |
| 23  | s3tests_boto3.functional.test_s3.test_post_object_expired_policy                         | FAIL  | ok     |
| 24  | s3tests_boto3.functional.test_s3.test_post_object_invalid_request_field_value            | FAIL  | ok     |
| 25  | s3tests_boto3.functional.test_s3.test_post_object_missing_expires_condition              | FAIL  | ok     |
| 26  | s3tests_boto3.functional.test_s3.test_post_object_missing_conditions_list                | FAIL  | ok     |
| 27  | s3tests_boto3.functional.test_s3.test_post_object_upload_size_limit_exceeded             | FAIL  | ok     |
| 28  | s3tests_boto3.functional.test_s3.test_post_object_missing_content_length_argument        | FAIL  | ok     |
| 29  | s3tests_boto3.functional.test_s3.test_post_object_invalid_content_length_argument        | FAIL  | ok     |
| 30  | s3tests_boto3.functional.test_s3.test_post_object_upload_size_below_minimum              | FAIL  | ok     |
| 31  | s3tests_boto3.functional.test_s3.test_post_object_empty_conditions                       | FAIL  | ok     |
| 32  | s3tests_boto3.functional.test_s3.test_post_object_tags_anonymous_request                 | FAIL  | FAIL   |
| 33  | s3tests_boto3.functional.test_s3.test_post_object_tags_authenticated_request             | FAIL  | ok     |

## ListObjects

Compatibility: 73/75/84

|    | Test                                                                                            | s3-gw | aws s3 |
|----|-------------------------------------------------------------------------------------------------|-------|--------|
| 1  | s3tests_boto3.functional.test_s3.test_bucket_list_empty                                         | ok    | ok     |
| 2  | s3tests_boto3.functional.test_s3.test_bucket_list_distinct                                      | ok    | ok     |
| 3  | s3tests_boto3.functional.test_s3.test_bucket_list_many                                          | ok    | ok     |
| 4  | s3tests_boto3.functional.test_s3.test_bucket_listv2_many                                        | ok    | ok     |
| 5  | s3tests_boto3.functional.test_s3.test_bucket_list_delimiter_basic                               | ok    | ok     |
| 6  | s3tests_boto3.functional.test_s3.test_bucket_listv2_delimiter_basic                             | ok    | ok     |
| 7  | s3tests_boto3.functional.test_s3.test_bucket_listv2_encoding_basic                              | FAIL  | FAIL   |
| 8  | s3tests_boto3.functional.test_s3.test_bucket_list_encoding_basic                                | FAIL  | FAIL   |
| 9  | s3tests_boto3.functional.test_s3.test_bucket_list_delimiter_prefix                              | ok    | ok     |
| 10 | s3tests_boto3.functional.test_s3.test_bucket_listv2_delimiter_prefix                            | ok    | ok     |
| 11 | s3tests_boto3.functional.test_s3.test_bucket_listv2_delimiter_prefix_ends_with_delimiter        | ok    | ok     |
| 12 | s3tests_boto3.functional.test_s3.test_bucket_list_delimiter_prefix_ends_with_delimiter          | ok    | ok     |
| 13 | s3tests_boto3.functional.test_s3.test_bucket_list_delimiter_alt                                 | ok    | ok     |
| 14 | s3tests_boto3.functional.test_s3.test_bucket_listv2_delimiter_alt                               | ok    | ok     |
| 15 | s3tests_boto3.functional.test_s3.test_bucket_list_delimiter_prefix_underscore                   | ok    | ok     |
| 16 | s3tests_boto3.functional.test_s3.test_bucket_listv2_delimiter_prefix_underscore                 | ok    | ok     |
| 17 | s3tests_boto3.functional.test_s3.test_bucket_list_delimiter_percentage                          | ERROR | ok     |
| 18 | s3tests_boto3.functional.test_s3.test_bucket_listv2_delimiter_percentage                        | ERROR | ok     |
| 19 | s3tests_boto3.functional.test_s3.test_bucket_list_delimiter_whitespace                          | ok    | ok     |
| 20 | s3tests_boto3.functional.test_s3.test_bucket_listv2_delimiter_whitespace                        | ok    | ok     |
| 21 | s3tests_boto3.functional.test_s3.test_bucket_list_delimiter_dot                                 | ok    | ok     |
| 22 | s3tests_boto3.functional.test_s3.test_bucket_listv2_delimiter_dot                               | ok    | ok     |
| 23 | s3tests_boto3.functional.test_s3.test_bucket_list_delimiter_unreadable                          | ok    | ok     |
| 24 | s3tests_boto3.functional.test_s3.test_bucket_listv2_delimiter_unreadable                        | ok    | ok     |
| 25 | s3tests_boto3.functional.test_s3.test_bucket_list_delimiter_empty                               | ok    | ok     |
| 26 | s3tests_boto3.functional.test_s3.test_bucket_listv2_delimiter_empty                             | ok    | ok     |
| 27 | s3tests_boto3.functional.test_s3.test_bucket_list_delimiter_none                                | ok    | ok     |
| 28 | s3tests_boto3.functional.test_s3.test_bucket_listv2_delimiter_none                              | ok    | ok     |
| 29 | s3tests_boto3.functional.test_s3.test_bucket_listv2_fetchowner_notempty                         | ok    | ok     |
| 30 | s3tests_boto3.functional.test_s3.test_bucket_listv2_fetchowner_defaultempty                     | ok    | ok     |
| 31 | s3tests_boto3.functional.test_s3.test_bucket_listv2_fetchowner_empty                            | ok    | ok     |
| 32 | s3tests_boto3.functional.test_s3.test_bucket_list_delimiter_not_exist                           | ok    | ok     |
| 33 | s3tests_boto3.functional.test_s3.test_bucket_listv2_delimiter_not_exist                         | ok    | ok     |
| 34 | s3tests_boto3.functional.test_s3.test_bucket_list_delimiter_not_skip_special                    | FAIL  |        |
| 35 | s3tests_boto3.functional.test_s3.test_bucket_list_prefix_basic                                  | ok    | ok     |
| 36 | s3tests_boto3.functional.test_s3.test_bucket_listv2_prefix_basic                                | ok    | ok     |
| 37 | s3tests_boto3.functional.test_s3.test_bucket_list_prefix_alt                                    | ok    | ok     |
| 38 | s3tests_boto3.functional.test_s3.test_bucket_listv2_prefix_alt                                  | ok    | ok     |
| 39 | s3tests_boto3.functional.test_s3.test_bucket_list_prefix_empty                                  | ok    | ok     |
| 40 | s3tests_boto3.functional.test_s3.test_bucket_listv2_prefix_empty                                | ok    | ok     |
| 41 | s3tests_boto3.functional.test_s3.test_bucket_list_prefix_none                                   | ok    | ok     |
| 42 | s3tests_boto3.functional.test_s3.test_bucket_listv2_prefix_none                                 | ok    | ok     |
| 43 | s3tests_boto3.functional.test_s3.test_bucket_list_prefix_not_exist                              | ok    | ok     |
| 44 | s3tests_boto3.functional.test_s3.test_bucket_listv2_prefix_not_exist                            | ok    | ok     |
| 45 | s3tests_boto3.functional.test_s3.test_bucket_list_prefix_unreadable                             | ok    | FAIL   |
| 46 | s3tests_boto3.functional.test_s3.test_bucket_listv2_prefix_unreadable                           | ok    | ok     |
| 47 | s3tests_boto3.functional.test_s3.test_bucket_list_prefix_delimiter_basic                        | ok    | ok     |
| 48 | s3tests_boto3.functional.test_s3.test_bucket_listv2_prefix_delimiter_basic                      | ok    | ok     |
| 49 | s3tests_boto3.functional.test_s3.test_bucket_list_prefix_delimiter_alt                          | ok    | ok     |
| 50 | s3tests_boto3.functional.test_s3.test_bucket_listv2_prefix_delimiter_alt                        | ok    | ok     |
| 51 | s3tests_boto3.functional.test_s3.test_bucket_list_prefix_delimiter_prefix_not_exist             | ok    | ok     |
| 52 | s3tests_boto3.functional.test_s3.test_bucket_listv2_prefix_delimiter_prefix_not_exist           | ok    | ok     |
| 53 | s3tests_boto3.functional.test_s3.test_bucket_list_prefix_delimiter_delimiter_not_exist          | ok    | ok     |
| 54 | s3tests_boto3.functional.test_s3.test_bucket_listv2_prefix_delimiter_delimiter_not_exist        | ok    | ok     |
| 55 | s3tests_boto3.functional.test_s3.test_bucket_list_prefix_delimiter_prefix_delimiter_not_exist   | ok    | ok     |
| 56 | s3tests_boto3.functional.test_s3.test_bucket_listv2_prefix_delimiter_prefix_delimiter_not_exist | ok    | ok     |
| 57 | s3tests_boto3.functional.test_s3.test_bucket_list_maxkeys_one                                   | ok    | ok     |
| 58 | s3tests_boto3.functional.test_s3.test_bucket_listv2_maxkeys_one                                 | ok    | ok     |
| 59 | s3tests_boto3.functional.test_s3.test_bucket_list_maxkeys_zero                                  | ok    | ok     |
| 60 | s3tests_boto3.functional.test_s3.test_bucket_listv2_maxkeys_zero                                | ok    | ok     |
| 61 | s3tests_boto3.functional.test_s3.test_bucket_list_maxkeys_none                                  | ok    | ok     |
| 62 | s3tests_boto3.functional.test_s3.test_bucket_listv2_maxkeys_none                                | ok    | ok     |
| 63 | s3tests_boto3.functional.test_s3.test_bucket_list_unordered                                     | FAIL  | FAIL   |
| 64 | s3tests_boto3.functional.test_s3.test_bucket_listv2_unordered                                   | FAIL  | FAIL   |
| 65 | s3tests_boto3.functional.test_s3.test_bucket_list_maxkeys_invalid                               | ok    | ok     |
| 66 | s3tests_boto3.functional.test_s3.test_bucket_list_marker_none                                   | ok    | ERROR  |
| 67 | s3tests_boto3.functional.test_s3.test_bucket_list_marker_empty                                  | ok    | ok     |
| 68 | s3tests_boto3.functional.test_s3.test_bucket_listv2_continuationtoken_empty                     | ERROR | ERROR  |
| 69 | s3tests_boto3.functional.test_s3.test_bucket_listv2_continuationtoken                           | ok    | ok     |
| 70 | s3tests_boto3.functional.test_s3.test_bucket_listv2_both_continuationtoken_startafter           | ok    | ERROR  |
| 71 | s3tests_boto3.functional.test_s3.test_bucket_list_marker_unreadable                             | ok    | ok     |
| 72 | s3tests_boto3.functional.test_s3.test_bucket_listv2_startafter_unreadable                       | ok    | ok     |
| 73 | s3tests_boto3.functional.test_s3.test_bucket_list_marker_not_in_list                            | ok    | ok     |
| 74 | s3tests_boto3.functional.test_s3.test_bucket_listv2_startafter_not_in_list                      | ok    | ok     |
| 75 | s3tests_boto3.functional.test_s3.test_bucket_list_marker_after_list                             | ok    | ok     |
| 76 | s3tests_boto3.functional.test_s3.test_bucket_listv2_startafter_after_list                       | ok    | ok     |
| 77 | s3tests_boto3.functional.test_s3.test_bucket_list_return_data                                   | ok    | ok     |
| 78 | s3tests_boto3.functional.test_s3.test_bucket_list_objects_anonymous                             | ok    | ok     |
| 79 | s3tests_boto3.functional.test_s3.test_bucket_listv2_objects_anonymous                           | ERROR | ok     |
| 80 | s3tests_boto3.functional.test_s3.test_bucket_list_objects_anonymous_fail                        | FAIL  | ok     |
| 81 | s3tests_boto3.functional.test_s3.test_bucket_listv2_objects_anonymous_fail                      | FAIL  | ok     |
| 82 | s3tests_boto3.functional.test_s3.test_bucket_list_special_prefix                                | ok    | ok     |
| 83 | s3tests_boto3.functional.test_s3.test_bucket_list_long_name                                     | ok    | ok     |
| 84 | s3tests_boto3.functional.test_s3.test_basic_key_count                                           | ok    | ok     |

## Object ACL

Compatibility:  4/10/19

|    | Test                                                                                  | s3-gw | aws s3 |
|----|---------------------------------------------------------------------------------------|-------|--------|
| 1  | s3tests_boto3.functional.test_headers.test_object_acl_create_contentlength_none       | ok    | ok     |
| 2  | s3tests_boto3.functional.test_s3.test_object_anon_put_write_access                    | ok    | ERROR  |
| 3  | s3tests_boto3.functional.test_s3.test_object_acl_default                              | ERROR | ok     |
| 4  | s3tests_boto3.functional.test_s3.test_object_acl_canned_during_create                 | ERROR | FAIL   |
| 5  | s3tests_boto3.functional.test_s3.test_object_acl_canned                               | ERROR | FAIL   |
| 6  | s3tests_boto3.functional.test_s3.test_object_acl_canned_publicreadwrite               | ERROR | FAIL   |
| 7  | s3tests_boto3.functional.test_s3.test_object_acl_canned_authenticatedread             | ERROR | FAIL   |
| 8  | s3tests_boto3.functional.test_s3.test_object_acl_canned_bucketownerread               | ERROR | ERROR  |
| 9  | s3tests_boto3.functional.test_s3.test_object_acl_canned_bucketownerfullcontrol        | ERROR | ERROR  |
| 10 | s3tests_boto3.functional.test_s3.test_object_acl_full_control_verify_owner            | ERROR | ERROR  |
| 11 | s3tests_boto3.functional.test_s3.test_object_acl_full_control_verify_attributes       | ERROR | ok     |
| 12 | s3tests_boto3.functional.test_s3.test_object_acl                                      | ERROR | FAIL   |
| 13 | s3tests_boto3.functional.test_s3.test_object_acl_write                                | ERROR | ok     |
| 14 | s3tests_boto3.functional.test_s3.test_object_acl_writeacp                             | ERROR | ok     |
| 15 | s3tests_boto3.functional.test_s3.test_object_acl_read                                 | ERROR | ok     |
| 16 | s3tests_boto3.functional.test_s3.test_object_acl_readacp                              | ERROR | ok     |
| 17 | s3tests_boto3.functional.test_s3.test_object_raw_authenticated_object_acl             | ok    | ok     |
| 18 | s3tests_boto3.functional.test_s3.test_object_raw_authenticated_object_gone            | ok    | ok     |
| 19 | s3tests_boto3.functional.test_s3.test_object_raw_get_bucket_acl                       | ERROR | ok     |

## Locking

Compatibility:  0/29/30

|    | Test                                                                                           | s3-gw | aws s3 |
|----|------------------------------------------------------------------------------------------------|-------|--------|
| 1  | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_lock                                 | ERROR | ok     |
| 2  | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_lock_invalid_bucket                  | FAIL  | ok     |
| 3  | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_lock_with_days_and_years             | FAIL  | ok     |
| 4  | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_lock_invalid_days                    | FAIL  | FAIL   |
| 5  | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_lock_invalid_years                   | FAIL  | ok     |
| 6  | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_lock_invalid_years                   | FAIL  | ok     |
| 7  | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_lock_invalid_status                  | FAIL  | ok     |
| 8  | s3tests_boto3.functional.test_s3.test_object_lock_suspend_versioning                           | FAIL  | ok     |
| 9  | s3tests_boto3.functional.test_s3.test_object_lock_get_obj_lock                                 | ERROR | ok     |
| 10 | s3tests_boto3.functional.test_s3.test_object_lock_get_obj_lock_invalid_bucket                  | FAIL  | ok     |
| 11 | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_retention                            | ERROR | ok     |
| 12 | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_retention_invalid_bucket             | FAIL  | ok     |
| 13 | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_retention_invalid_mode               | FAIL  | ok     |
| 14 | s3tests_boto3.functional.test_s3.test_object_lock_get_obj_retention                            | ERROR | ok     |
| 15 | s3tests_boto3.functional.test_s3.test_object_lock_get_obj_retention_invalid_bucket             | FAIL  | ok     |
| 16 | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_retention_versionid                  | ERROR | ok     |
| 17 | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_retention_override_default_retention | ERROR | ok     |
| 18 | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_retention_increase_period            | ERROR | ok     |
| 19 | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_retention_shorten_period             | ERROR | ok     |
| 20 | s3tests_boto3.functional.test_s3.test_object_lock_put_obj_retention_shorten_period_bypass      | ERROR | ok     |
| 21 | s3tests_boto3.functional.test_s3.test_object_lock_delete_object_with_retention                 | ERROR | ok     |
| 22 | s3tests_boto3.functional.test_s3.test_object_lock_put_legal_hold                               | ERROR | ok     |
| 23 | s3tests_boto3.functional.test_s3.test_object_lock_put_legal_hold_invalid_bucket                | FAIL  | ok     |
| 24 | s3tests_boto3.functional.test_s3.test_object_lock_put_legal_hold_invalid_status                | FAIL  | ok     |
| 25 | s3tests_boto3.functional.test_s3.test_object_lock_get_legal_hold                               | ERROR | ok     |
| 26 | s3tests_boto3.functional.test_s3.test_object_lock_get_legal_hold_invalid_bucket                | FAIL  | ok     |
| 27 | s3tests_boto3.functional.test_s3.test_object_lock_delete_object_with_legal_hold_on             | ERROR | ok     |
| 28 | s3tests_boto3.functional.test_s3.test_object_lock_delete_object_with_legal_hold_off            | ERROR | ok     |
| 29 | s3tests_boto3.functional.test_s3.test_object_lock_get_obj_metadata                             | ERROR | ok     |
| 30 | s3tests_boto3.functional.test_s3.test_object_lock_uploading_obj                                | ERROR | ok     |

## Multipart

Compatibility: 0/19/22

|    | Test                                                                             | s3-gw | aws s3 |
|----|----------------------------------------------------------------------------------|-------|--------|
| 1  | s3tests_boto3.functional.test_s3.test_multipart_upload_empty                     | ERROR | FAIL   |
| 2  | s3tests_boto3.functional.test_s3.test_multipart_upload_small                     | ERROR | ok     |
| 3  | s3tests_boto3.functional.test_s3.test_multipart_copy_small                       | ERROR | ok     |
| 4  | s3tests_boto3.functional.test_s3.test_multipart_copy_invalid_range               | ERROR | FAIL   |
| 5  | s3tests_boto3.functional.test_s3.test_multipart_copy_improper_range              | ERROR | ok     |
| 6  | s3tests_boto3.functional.test_s3.test_multipart_copy_without_range               | ERROR | ok     |
| 7  | s3tests_boto3.functional.test_s3.test_multipart_copy_special_names               | ERROR | ok     |
| 8  | s3tests_boto3.functional.test_s3.test_multipart_upload                           | ERROR | ok     |
| 10 | s3tests_boto3.functional.test_s3.test_multipart_upload_resend_part               | ERROR | ok     |
| 11 | s3tests_boto3.functional.test_s3.test_multipart_upload_multiple_sizes            | ERROR | ok     |
| 12 | s3tests_boto3.functional.test_s3.test_multipart_copy_multiple_sizes              | ERROR | ok     |
| 13 | s3tests_boto3.functional.test_s3.test_multipart_upload_size_too_small            | ERROR | ok     |
| 14 | s3tests_boto3.functional.test_s3.test_multipart_upload_contents                  | ERROR | ok     |
| 15 | s3tests_boto3.functional.test_s3.test_multipart_upload_overwrite_existing_object | ERROR | ok     |
| 16 | s3tests_boto3.functional.test_s3.test_abort_multipart_upload                     | ERROR | ok     |
| 17 | s3tests_boto3.functional.test_s3.test_abort_multipart_upload_not_found           | ERROR | ok     |
| 18 | s3tests_boto3.functional.test_s3.test_list_multipart_upload                      | ERROR | ok     |
| 19 | s3tests_boto3.functional.test_s3.test_multipart_upload_missing_part              | ERROR | ok     |
| 20 | s3tests_boto3.functional.test_s3.test_multipart_upload_incorrect_etag            | ERROR | ok     |
| 21 | s3tests_boto3.functional.test_s3.test_multipart_resend_first_finishes_last       | ERROR | ERROR  |
| 22 | s3tests_boto3.functional.test_s3.test_atomic_multipart_upload_write              | ERROR | ok     |

## Tagging

Compatibility: 8/8/11

|    | Test                                                       | s3-gw | aws s3 |
|----|------------------------------------------------------------|-------|--------|
| 1  | s3tests_boto3.functional.test_s3.test_set_bucket_tagging   | FAIL  | FAIL   |
| 2  | s3tests_boto3.functional.test_s3.test_get_obj_tagging      | ok    | ok     |
| 3  | s3tests_boto3.functional.test_s3.test_get_obj_head_tagging | ok    | ok     |
| 4  | s3tests_boto3.functional.test_s3.test_put_max_tags         | ok    | ok     |
| 5  | s3tests_boto3.functional.test_s3.test_put_excess_tags      | FAIL  | FAIL   |
| 6  | s3tests_boto3.functional.test_s3.test_put_max_kvsize_tags  | ok    | ok     |
| 7  | s3tests_boto3.functional.test_s3.test_put_excess_key_tags  | ok    | ok     |
| 8  | s3tests_boto3.functional.test_s3.test_put_excess_val_tags  | ok    | ok     |
| 9  | s3tests_boto3.functional.test_s3.test_put_modify_tags      | FAIL  | FAIL   |
| 10 | s3tests_boto3.functional.test_s3.test_put_delete_tags      | ok    | ok     |
| 11 | s3tests_boto3.functional.test_s3.test_put_obj_with_tags    | ok    | ok     |

## Versioning

Compatibility: 11/24/26

|    | Test                                                                                        | s3-gw | aws s3 |
|----|---------------------------------------------------------------------------------------------|-------|--------|
| 1  | s3tests_boto3.functional.test_s3.test_versioning_bucket_create_suspend                      | ok    | ok     |
| 2  | s3tests_boto3.functional.test_s3.test_versioning_obj_create_read_remove                     | ok    | ok     |
| 3  | s3tests_boto3.functional.test_s3.test_versioning_obj_create_read_remove_head                | ok    | ok     |
| 4  | s3tests_boto3.functional.test_s3.test_versioning_obj_plain_null_version_removal             | ERROR | ok     |
| 5  | s3tests_boto3.functional.test_s3.test_versioning_obj_plain_null_version_overwrite           | ERROR | ok     |
| 6  | s3tests_boto3.functional.test_s3.test_versioning_obj_plain_null_version_overwrite_suspended | ERROR | ok     |
| 7  | s3tests_boto3.functional.test_s3.test_versioning_obj_suspend_versions                       | ERROR | ok     |
| 8  | s3tests_boto3.functional.test_s3.test_versioning_obj_create_versions_remove_all             | ok    | ok     |
| 9  | s3tests_boto3.functional.test_s3.test_versioning_obj_create_versions_remove_special_names   | ok    | ok     |
| 10 | s3tests_boto3.functional.test_s3.test_versioning_obj_create_overwrite_multipart             | ERROR | ok     |
| 11 | s3tests_boto3.functional.test_s3.test_versioning_obj_list_marker                            | ok    | ok     |
| 12 | s3tests_boto3.functional.test_s3.test_versioning_copy_obj_version                           | ok    | ok     |
| 13 | s3tests_boto3.functional.test_s3.test_versioning_multi_object_delete                        | ok    | ok     |
| 14 | s3tests_boto3.functional.test_s3.test_versioning_multi_object_delete_with_marker            | ok    | ok     |
| 15 | s3tests_boto3.functional.test_s3.test_versioning_multi_object_delete_with_marker_create     | ok    | ok     |
| 16 | s3tests_boto3.functional.test_s3.test_versioned_object_acl                                  | ERROR | FAIL   |
| 17 | s3tests_boto3.functional.test_s3.test_versioned_object_acl_no_version_specified             | ERROR | FAIL   |
| 18 | s3tests_boto3.functional.test_s3.test_versioned_concurrent_object_create_concurrent_remove  | ERROR | ok     |
| 19 | s3tests_boto3.functional.test_s3.test_versioned_concurrent_object_create_and_remove         | ERROR | ok     |
| 20 | s3tests_boto3.functional.test_s3.test_versioning_bucket_atomic_upload_return_version_id     | ok    | ok     |
| 21 | s3tests_boto3.functional.test_s3.test_versioning_bucket_multipart_upload_return_version_id  | ERROR | ok     |
| 22 | s3tests_boto3.functional.test_s3.test_bucket_list_return_data_versioning                    | ERROR | ok     |
| 23 | s3tests_boto3.functional.test_s3.test_object_copy_versioned_bucket                          | ok    | ok     |
| 24 | s3tests_boto3.functional.test_s3.test_object_copy_versioned_url_encoding                    | ok    | ok     |
| 25 | s3tests_boto3.functional.test_s3.test_object_copy_versioning_multipart_upload               | ERROR | ok     |
| 26 | s3tests_boto3.functional.test_s3.test_multipart_copy_versioned                              | ERROR | ok     |

## Bucket

Compatibility:  32/45/59

|    | Test                                                                                         | s3-gw | aws s3 |
|----|----------------------------------------------------------------------------------------------|-------|--------|
| 1  | s3tests_boto3.functional.test_headers.test_bucket_create_bad_authorization_invalid_aws2      | FAIL  | FAIL   |
| 2  | s3tests_boto3.functional.test_headers.test_bucket_create_bad_ua_empty_aws2                   | ERROR | ok     |
| 3  | s3tests_boto3.functional.test_headers.test_bucket_create_bad_ua_none_aws2                    | ERROR | ok     |
| 4  | s3tests_boto3.functional.test_headers.test_bucket_create_bad_date_invalid_aws2               | FAIL  | ok     |
| 5  | s3tests_boto3.functional.test_headers.test_bucket_create_bad_date_empty_aws2                 | FAIL  | ok     |
| 6  | s3tests_boto3.functional.test_headers.test_bucket_create_bad_date_none_aws2                  | FAIL  | FAIL   |
| 7  | s3tests_boto3.functional.test_headers.test_bucket_create_bad_date_before_today_aws2          | FAIL  | ok     |
| 8  | s3tests_boto3.functional.test_headers.test_bucket_create_bad_date_after_today_aws2           | FAIL  | ok     |
| 9  | s3tests_boto3.functional.test_headers.test_bucket_create_bad_date_before_epoch_aws2          | FAIL  | ok     |
| 10 | s3tests_boto3.functional.test_headers.test_bucket_create_contentlength_none                  | ok    | ok     |
| 11 | s3tests_boto3.functional.test_headers.test_bucket_put_bad_canned_acl                         | ok    | ok     |
| 12 | s3tests_boto3.functional.test_headers.test_bucket_create_bad_expect_mismatch                 | ERROR | ok     |
| 13 | s3tests_boto3.functional.test_headers.test_bucket_create_bad_expect_empty                    | ok    | ok     |
| 14 | s3tests_boto3.functional.test_headers.test_bucket_create_bad_contentlength_empty             | FAIL  | ok     |
| 15 | s3tests_boto3.functional.test_headers.test_bucket_create_bad_contentlength_negative          | ok    | ok     |
| 16 | s3tests_boto3.functional.test_headers.test_bucket_create_bad_contentlength_none              | ok    | ok     |
| 17 | s3tests_boto3.functional.test_headers.test_bucket_create_bad_authorization_empty             | FAIL  | FAIL   |
| 18 | s3tests_boto3.functional.test_headers.test_bucket_create_bad_authorization_none              | FAIL  | FAIL   |
| 19 | s3tests_boto3.functional.test_s3.test_bucket_notexist                                        | ok    | ok     |
| 20 | s3tests_boto3.functional.test_s3.test_bucketv2_notexist                                      | ok    | ok     |
| 21 | s3tests_boto3.functional.test_s3.test_bucket_delete_notexist                                 | ok    | ok     |
| 22 | s3tests_boto3.functional.test_s3.test_bucket_delete_nonempty                                 | ok    | ok     |
| 23 | s3tests_boto3.functional.test_s3.test_bucket_concurrent_set_canned_acl                       | FAIL  | FAIL   |
| 24 | s3tests_boto3.functional.test_s3.test_bucket_create_delete                                   | FAIL  | ok     |
| 25 | s3tests_boto3.functional.test_s3.test_bucket_head                                            | ok    | ok     |
| 26 | s3tests_boto3.functional.test_s3.test_bucket_head_notexist                                   | ok    | ok     |
| 27 | s3tests_boto3.functional.test_s3.test_bucket_head_extended                                   | ERROR | ERROR  |
| 28 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_bad_starts_nonalpha               | ok    | ok     |
| 29 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_bad_short_empty                   | ERROR | ERROR  |
| 30 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_bad_short_one                     | ok    | ok     |
| 31 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_bad_short_two                     | ok    | ok     |
| 32 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_bad_long                          | ERROR | ERROR  |
| 33 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_good_long_60                      | ok    | ok     |
| 34 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_good_long_61                      | ok    | ok     |
| 35 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_good_long_62                      | ok    | ok     |
| 36 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_good_long_63                      | ok    | ok     |
| 37 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_bad_ip                            | FAIL  | FAIL   |
| 38 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_bad_punctuation                   | ERROR | ERROR  |
| 39 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_dns_underscore                    | ok    | ok     |
| 40 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_dns_long                          | ok    | ok     |
| 41 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_dns_dash_at_end                   | ok    | ok     |
| 42 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_dns_dot_dot                       | ok    | ok     |
| 43 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_dns_dot_dash                      | ok    | ok     |
| 44 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_dns_dash_dot                      | ok    | ok     |
| 45 | s3tests_boto3.functional.test_s3.test_bucket_create_exists                                   | ERROR | ok     |
| 46 | s3tests_boto3.functional.test_s3.test_bucket_get_location                                    | FAIL  | ERROR  |
| 47 | s3tests_boto3.functional.test_s3.test_bucket_create_exists_nonowner                          | FAIL  | ok     |
| 48 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_good_starts_alpha                 | ok    | ok     |
| 49 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_good_starts_digit                 | ok    | ok     |
| 50 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_good_contains_period              | ok    | ok     |
| 51 | s3tests_boto3.functional.test_s3.test_bucket_create_naming_good_contains_hyphen              | ok    | ok     |
| 52 | s3tests_boto3.functional.test_s3.test_bucket_recreate_not_overriding                         | ERROR | ok     |
| 53 | s3tests_boto3.functional.test_s3.test_bucket_create_special_key_names                        | ERROR | ok     |
| 54 | s3tests_boto3.functional.test_s3.test_bucket_policy_set_condition_operator_end_with_IfExists | ERROR | FAIL   |
| 55 | s3tests_boto3.functional.test_s3.test_buckets_create_then_list                               | ok    | ok     |
| 56 | s3tests_boto3.functional.test_s3.test_buckets_list_ctime                                     | FAIL  | FAIL   |
| 57 | s3tests_boto3.functional.test_s3.test_list_buckets_anonymous                                 | ok    | ERROR  |
| 58 | s3tests_boto3.functional.test_s3.test_list_buckets_invalid_auth                              | ok    | ok     |
| 59 | s3tests_boto3.functional.test_s3.test_list_buckets_bad_auth                                  | ok    | ok     |

## Bucket ACL

Compatibility:  0/16/33

|    | Test                                                                                       | s3-gw | aws s3 |
|----|--------------------------------------------------------------------------------------------|-------|--------|
| 1  | s3tests_boto3.functional.test_s3.test_bucket_recreate_overwrite_acl                        | FAIL  | FAIL   |
| 2  | s3tests_boto3.functional.test_s3.test_bucket_recreate_new_acl                              | FAIL  | FAIL   |
| 3  | s3tests_boto3.functional.test_s3.test_bucket_acl_default                                   | ERROR | ok     |
| 4  | s3tests_boto3.functional.test_s3.test_bucket_acl_canned_during_create                      | ERROR | FAIL   |
| 5  | s3tests_boto3.functional.test_s3.test_bucket_acl_canned                                    | ERROR | FAIL   |
| 6  | s3tests_boto3.functional.test_s3.test_bucket_acl_canned_publicreadwrite                    | ERROR | FAIL   |
| 7  | s3tests_boto3.functional.test_s3.test_bucket_acl_canned_authenticatedread                  | ERROR | FAIL   |
| 8  | s3tests_boto3.functional.test_s3.test_bucket_acl_grant_userid_fullcontrol                  | ERROR | ERROR  |
| 9  | s3tests_boto3.functional.test_s3.test_bucket_acl_grant_userid_read                         | ERROR | ERROR  |
| 10 | s3tests_boto3.functional.test_s3.test_bucket_acl_grant_userid_readacp                      | ERROR | ERROR  |
| 11 | s3tests_boto3.functional.test_s3.test_bucket_acl_grant_userid_write                        | ERROR | ERROR  |
| 12 | s3tests_boto3.functional.test_s3.test_bucket_acl_grant_userid_writeacp                     | ERROR | ERROR  |
| 13 | s3tests_boto3.functional.test_s3.test_bucket_acl_grant_nonexist_user                       | ERROR | ok     |
| 14 | s3tests_boto3.functional.test_s3.test_bucket_acl_no_grants                                 | ERROR | FAIL   |
| 15 | s3tests_boto3.functional.test_s3.test_bucket_acl_grant_email                               | ERROR | ERROR  |
| 16 | s3tests_boto3.functional.test_s3.test_bucket_acl_grant_email_not_exist                     | ERROR | ok     |
| 17 | s3tests_boto3.functional.test_s3.test_bucket_acl_revoke_all                                | ERROR | ok     |
| 18 | s3tests_boto3.functional.test_s3.test_bucket_acl_canned_private_to_private                 | ERROR | ok     |
| 19 | s3tests_boto3.functional.test_s3.test_bucket_header_acl_grants                             | ERROR | FAIL   |
| 20 | s3tests_boto3.functional.test_s3.test_access_bucket_private_object_private                 | ERROR | ok     |
| 21 | s3tests_boto3.functional.test_s3.test_access_bucket_private_objectv2_private               | ERROR | ok     |
| 22 | s3tests_boto3.functional.test_s3.test_access_bucket_private_object_publicread              | ERROR | ok     |
| 23 | s3tests_boto3.functional.test_s3.test_access_bucket_private_objectv2_publicread            | ERROR | ok     |
| 24 | s3tests_boto3.functional.test_s3.test_access_bucket_private_object_publicreadwrite         | ERROR | ok     |
| 25 | s3tests_boto3.functional.test_s3.test_access_bucket_private_objectv2_publicreadwrite       | ERROR | ok     |
| 26 | s3tests_boto3.functional.test_s3.test_access_bucket_publicread_object_private              | ERROR | ok     |
| 27 | s3tests_boto3.functional.test_s3.test_access_bucket_publicread_object_publicread           | ERROR | ok     |
| 28 | s3tests_boto3.functional.test_s3.test_access_bucket_publicread_object_publicreadwrite      | ERROR | ok     |
| 29 | s3tests_boto3.functional.test_s3.test_access_bucket_publicreadwrite_object_private         | ERROR | FAIL   |
| 30 | s3tests_boto3.functional.test_s3.test_access_bucket_publicreadwrite_object_publicread      | ERROR | FAIL   |
| 31 | s3tests_boto3.functional.test_s3.test_access_bucket_publicreadwrite_object_publicreadwrite | ERROR | FAIL   |
| 32 | s3tests_boto3.functional.test_s3.test_object_raw_authenticated_bucket_acl                  | ERROR | ok     |
| 33 | s3tests_boto3.functional.test_s3.test_object_raw_authenticated_bucket_gone                 | ERROR | ok     |

## CORS

Compatibility: 3/3/4

|   | Test                                                       | s3-gw  | aws s3 |
|---|------------------------------------------------------------|--------|--------|
| 1 | s3tests_boto3.functional.test_s3.test_set_cors             | ok     | ok     |
| 2 | s3tests_boto3.functional.test_s3.test_cors_origin_response | FAIL   | FAIL   |
| 3 | s3tests_boto3.functional.test_s3.test_cors_origin_wildcard | ok     | ok     |
| 4 | s3tests_boto3.functional.test_s3.test_cors_header_option   | ok     | ok     |

## Encryption

Compatibility: 0/16/29

|    | Test                                                                                     | s3-gw       | aws s3 |
|----|------------------------------------------------------------------------------------------|-------------|--------|
| 1  | s3tests_boto3.functional.test_s3.test_encrypted_transfer_1b                              | ERROR       | ok     |
| 2  | s3tests_boto3.functional.test_s3.test_encrypted_transfer_1kb                             | ERROR       | ok     |
| 3  | s3tests_boto3.functional.test_s3.test_encrypted_transfer_1MB                             | ERROR       | ok     |
| 4  | s3tests_boto3.functional.test_s3.test_encrypted_transfer_13b                             | ERROR       | ok     |
| 5  | s3tests_boto3.functional.test_s3.test_encryption_sse_c_method_head                       | ERROR       | ok     |
| 6  | s3tests_boto3.functional.test_s3.test_encryption_sse_c_present                           | ERROR       | ok     |
| 7  | s3tests_boto3.functional.test_s3.test_encryption_sse_c_other_key                         | ERROR       | FAIL   |
| 8  | s3tests_boto3.functional.test_s3.test_encryption_sse_c_invalid_md5                       | UNSUPPORTED | ok     |
| 9  | s3tests_boto3.functional.test_s3.test_encryption_sse_c_no_md5                            | FAIL        | ok     |
| 10 | s3tests_boto3.functional.test_s3.test_encryption_sse_c_no_key                            | FAIL        | ok     |
| 11 | s3tests_boto3.functional.test_s3.test_encryption_key_no_sse_c                            | FAIL        | ok     |
| 12 | s3tests_boto3.functional.test_s3.test_encryption_sse_c_multipart_upload                  | ERROR       | ok     |
| 13 | s3tests_boto3.functional.test_s3.test_encryption_sse_c_multipart_invalid_chunks_1        | FAIL        | ok     |
| 14 | s3tests_boto3.functional.test_s3.test_encryption_sse_c_multipart_invalid_chunks_2        | FAIL        | ok     |
| 15 | s3tests_boto3.functional.test_s3.test_encryption_sse_c_multipart_bad_download            | ERROR       | FAIL   |
| 16 | s3tests_boto3.functional.test_s3.test_encryption_sse_c_post_object_authenticated_request | FAIL        | ok     |
| 17 | s3tests_boto3.functional.test_s3.test_sse_kms_method_head                                | ERROR       | ERROR  |
| 18 | s3tests_boto3.functional.test_s3.test_sse_kms_present                                    | ERROR       | ERROR  |
| 19 | s3tests_boto3.functional.test_s3.test_sse_kms_no_key                                     | FAIL        | FAIL   |
| 20 | s3tests_boto3.functional.test_s3.test_sse_kms_not_declared                               | FAIL        | ok     |
| 21 | s3tests_boto3.functional.test_s3.test_sse_kms_multipart_upload                           | ERROR       | ERROR  |
| 22 | s3tests_boto3.functional.test_s3.test_sse_kms_multipart_invalid_chunks_1                 | ERROR       | ERROR  |
| 23 | s3tests_boto3.functional.test_s3.test_sse_kms_multipart_invalid_chunks_2                 | ERROR       | ERROR  |
| 24 | s3tests_boto3.functional.test_s3.test_sse_kms_post_object_authenticated_request          | FAIL        | FAIL   |
| 25 | s3tests_boto3.functional.test_s3.test_sse_kms_transfer_1b                                | ERROR       | ERROR  |
| 26 | s3tests_boto3.functional.test_s3.test_sse_kms_transfer_1kb                               | ERROR       | ERROR  |
| 27 | s3tests_boto3.functional.test_s3.test_sse_kms_transfer_1MB                               | ERROR       | ERROR  |
| 28 | s3tests_boto3.functional.test_s3.test_sse_kms_transfer_13b                               | ERROR       | ERROR  |
| 29 | s3tests_boto3.functional.test_s3.test_sse_kms_read_declare                               | ERROR       | ok     |

## Lifecycle

Compatibility: 0/18/29

|    | Test                                                                            | s3-gw | aws s3 |
|----|---------------------------------------------------------------------------------|-------|--------|
| 1  | s3tests_boto3.functional.test_s3.test_lifecycle_set                             | ERROR | ok     |
| 2  | s3tests_boto3.functional.test_s3.test_lifecycle_get                             | ERROR | ok     |
| 3  | s3tests_boto3.functional.test_s3.test_lifecycle_get_no_id                       | ERROR | ok     |
| 4  | s3tests_boto3.functional.test_s3.test_lifecycle_expiration                      | ERROR | FAIL   |
| 5  | s3tests_boto3.functional.test_s3.test_lifecyclev2_expiration                    | ERROR | FAIL   |
| 6  | s3tests_boto3.functional.test_s3.test_lifecycle_expiration_versioning_enabled   | ERROR | ok     |
| 7  | s3tests_boto3.functional.test_s3.test_lifecycle_expiration_tags1                | ERROR | ERROR  |
| 8  | s3tests_boto3.functional.test_s3.test_lifecycle_expiration_tags2                | ERROR | ERROR  |
| 9  | s3tests_boto3.functional.test_s3.test_lifecycle_expiration_versioned_tags2      | ERROR | ERROR  |
| 10 | s3tests_boto3.functional.test_s3.test_lifecycle_expiration_noncur_tags1         | ERROR | ERROR  |
| 11 | s3tests_boto3.functional.test_s3.test_lifecycle_id_too_long                     | FAIL  | ok     |
| 12 | s3tests_boto3.functional.test_s3.test_lifecycle_same_id                         | FAIL  | ok     |
| 13 | s3tests_boto3.functional.test_s3.test_lifecycle_invalid_status                  | FAIL  | ok     |
| 14 | s3tests_boto3.functional.test_s3.test_lifecycle_set_date                        | ERROR | ok     |
| 15 | s3tests_boto3.functional.test_s3.test_lifecycle_set_invalid_date                | FAIL  | ok     |
| 16 | s3tests_boto3.functional.test_s3.test_lifecycle_expiration_date                 | ERROR | FAIL   |
| 17 | s3tests_boto3.functional.test_s3.test_lifecycle_expiration_days0                | ERROR | ok     |
| 18 | s3tests_boto3.functional.test_s3.test_lifecycle_expiration_header_put           | ERROR | ok     |
| 19 | s3tests_boto3.functional.test_s3.test_lifecycle_expiration_header_head          | ERROR | ok     |
| 20 | s3tests_boto3.functional.test_s3.test_lifecycle_expiration_header_tags_head     | ERROR | FAIL   |
| 21 | s3tests_boto3.functional.test_s3.test_lifecycle_expiration_header_and_tags_head | ERROR | ok     |
| 22 | s3tests_boto3.functional.test_s3.test_lifecycle_set_noncurrent                  | ERROR | ok     |
| 23 | s3tests_boto3.functional.test_s3.test_lifecycle_noncur_expiration               | ERROR | FAIL   |
| 24 | s3tests_boto3.functional.test_s3.test_lifecycle_set_deletemarker                | ERROR | ok     |
| 25 | s3tests_boto3.functional.test_s3.test_lifecycle_set_filter                      | ERROR | ok     |
| 26 | s3tests_boto3.functional.test_s3.test_lifecycle_set_empty_filter                | ERROR | ok     |
| 27 | s3tests_boto3.functional.test_s3.test_lifecycle_deletemarker_expiration         | ERROR | FAIL   |
| 28 | s3tests_boto3.functional.test_s3.test_lifecycle_set_multipart                   | ERROR | ok     |
| 29 | s3tests_boto3.functional.test_s3.test_lifecycle_multipart_expiration            | ERROR | FAIL   |

## Policy and replication

Compatibility:  0/20/35

|    | Test                                                                                | s3-gw | aws s3 |
|----|-------------------------------------------------------------------------------------|-------|--------|
| 1  | s3tests_boto3.functional.test_s3.test_bucket_policy                                 | ERROR | ok     |
| 2  | s3tests_boto3.functional.test_s3.test_bucketv2_policy                               | ERROR | ok     |
| 3  | s3tests_boto3.functional.test_s3.test_bucket_policy_acl                             | ERROR | ok     |
| 4  | s3tests_boto3.functional.test_s3.test_bucketv2_policy_acl                           | ERROR | ok     |
| 5  | s3tests_boto3.functional.test_s3.test_bucket_policy_different_tenant                | ERROR | ERROR  |
| 6  | s3tests_boto3.functional.test_s3.test_bucketv2_policy_different_tenant              | ERROR | ERROR  |
| 7  | s3tests_boto3.functional.test_s3.test_bucket_policy_another_bucket                  | ERROR | ERROR  |
| 8  | s3tests_boto3.functional.test_s3.test_bucketv2_policy_another_bucket                | ERROR | ERROR  |
| 9  | s3tests_boto3.functional.test_s3.test_bucket_policy_get_obj_existing_tag            | ERROR | ok     |
| 10 | s3tests_boto3.functional.test_s3.test_bucket_policy_get_obj_tagging_existing_tag    | ERROR | ok     |
| 11 | s3tests_boto3.functional.test_s3.test_bucket_policy_put_obj_tagging_existing_tag    | ERROR | ok     |
| 12 | s3tests_boto3.functional.test_s3.test_bucket_policy_put_obj_copy_source             | ERROR | ok     |
| 13 | s3tests_boto3.functional.test_s3.test_bucket_policy_put_obj_copy_source_meta        | ERROR | ok     |
| 14 | s3tests_boto3.functional.test_s3.test_bucket_policy_put_obj_acl                     | ERROR | ok     |
| 15 | s3tests_boto3.functional.test_s3.test_bucket_policy_put_obj_grant                   | ERROR | ok     |
| 16 | s3tests_boto3.functional.test_s3.test_bucket_policy_put_obj_enc                     | ERROR | ERROR  |
| 17 | s3tests_boto3.functional.test_s3.test_bucket_policy_put_obj_request_obj_tag         | ERROR | FAIL   |
| 18 | s3tests_boto3.functional.test_s3.test_bucket_policy_get_obj_acl_existing_tag        | ERROR | ok     |
| 19 | s3tests_boto3.functional.test_s3.test_user_policy                                   | ERROR | ERROR  |
| 20 | s3tests_boto3.functional.test_s3.test_get_bucket_policy_status                      | ERROR | ERROR  |
| 21 | s3tests_boto3.functional.test_s3.test_get_public_acl_bucket_policy_status           | ERROR | ERROR  |
| 22 | s3tests_boto3.functional.test_s3.test_get_authpublic_acl_bucket_policy_status       | ERROR | ERROR  |
| 23 | s3tests_boto3.functional.test_s3.test_get_publicpolicy_acl_bucket_policy_status     | ERROR | ERROR  |
| 24 | s3tests_boto3.functional.test_s3.test_get_nonpublicpolicy_acl_bucket_policy_status  | ERROR | ERROR  |
| 25 | s3tests_boto3.functional.test_s3.test_get_nonpublicpolicy_deny_bucket_policy_status | ERROR | ERROR  |
| 26 | s3tests_boto3.functional.test_s3.test_get_default_public_block                      | ERROR | ERROR  |
| 27 | s3tests_boto3.functional.test_s3.test_put_public_block                              | ERROR | ok     |
| 28 | s3tests_boto3.functional.test_s3.test_block_public_put_bucket_acls                  | ERROR | ok     |
| 29 | s3tests_boto3.functional.test_s3.test_block_public_object_canned_acls               | ERROR | ok     |
| 30 | s3tests_boto3.functional.test_s3.test_block_public_policy                           | ERROR | ok     |
| 31 | s3tests_boto3.functional.test_s3.test_ignore_public_acls                            | ERROR | FAIL   |
| 32 | s3tests_boto3.functional.test_s3.test_get_tags_acl_public                           | ERROR | ok     |
| 33 | s3tests_boto3.functional.test_s3.test_put_tags_acl_public                           | ERROR | ok     |
| 34 | s3tests_boto3.functional.test_s3.test_delete_tags_obj_public                        | ERROR | ok     |
| 35 | s3tests_boto3.functional.test_s3.test_multipart_upload_on_a_bucket_with_policy      | ERROR | ok     |

## Others

Compatibility: 2/3/6

|   | Test                                                        | s3-gw | aws s3 |
|---|-------------------------------------------------------------|-------|--------|
| 1 | s3tests_boto3.functional.test_s3.test_100_continue          | FAIL  | ok     |
| 2 | s3tests_boto3.functional.test_s3.test_account_usage         | ERROR | ERROR  |
| 3 | s3tests_boto3.functional.test_s3.test_head_bucket_usage     | ERROR | ERROR  |
| 4 | s3tests_boto3.functional.test_s3.test_logging_toggle        | ERROR | ERROR  |
| 5 | s3tests_boto3.functional.test_s3.test_multi_object_delete   | ok    | ok     |
| 6 | s3tests_boto3.functional.test_s3.test_multi_objectv2_delete | ok    | ok     |
