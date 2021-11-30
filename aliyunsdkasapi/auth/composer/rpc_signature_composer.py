# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# coding=utf-8
from aliyunsdkcore.vendored.six import iteritems
from aliyunsdkcore.vendored.six.moves.urllib.parse import urlencode
from aliyunsdkcore.vendored.six.moves.urllib.request import pathname2url

from aliyunsdkcore.auth.algorithm import sha_hmac1 as mac1
from aliyunsdkasapi.auth.composer import sha_hmac256 as mac256
from aliyunsdkasapi.auth.composer import sm3_hmac as mac3
from aliyunsdkcore.utils import parameter_helper as helper


# this function will append the necessary parameters for signers process.
# parameters: the orignal parameters
# signers: sha_hmac1 or sha_hmac256
# accessKeyId: this is aliyun_access_key_id
# format: XML or JSON
def __refresh_sign_parameters(
        parameters,
        access_key_id,
        accept_format="JSON",
        signer=mac1):
    if parameters is None or not isinstance(parameters, dict):
        parameters = dict()
    if 'Signature' in parameters:
        del parameters['Signature']
    parameters["Timestamp"] = helper.get_iso_8061_date()
    parameters["SignatureMethod"] = signer.get_signer_name()
    parameters["SignatureType"] = signer.get_signer_type()
    parameters["SignatureVersion"] = "2.1"
    parameters["SignatureNonce"] = helper.get_uuid()
    parameters["AccessKeyId"] = access_key_id
    if accept_format is not None:
        parameters["Format"] = accept_format
    return parameters


def __pop_standard_urlencode(query):
    ret = query.replace('+', '%20')
    ret = ret.replace('*', '%2A')
    ret = ret.replace('%7E', '~')
    return ret


def __compose_string_to_sign(method, queries):
    sorted_parameters = sorted(iteritems(queries), key=lambda queries: queries[0])
    sorted_query_string = __pop_standard_urlencode(urlencode(sorted_parameters))
    canonicalized_query_string = __pop_standard_urlencode(pathname2url(sorted_query_string))
    string_to_sign = method + "&%2F&" + canonicalized_query_string
    return string_to_sign


def __get_signature(string_to_sign, secret, signer=mac1):
    return signer.get_sign_string(string_to_sign, secret + '&')


def get_signed_url(params, ak, secret, accept_format, method, body_params, signer=mac256, header=None):
    if header is None:
        header = {}
    SIGN_METHODS = {"HMAC-SHA256": mac256, "HMAC-SHA1": mac1, "HMAC-SM3": mac3}
    if "SignatureMethod" in params and params["SignatureMethod"] in SIGN_METHODS:
        signer = SIGN_METHODS[params["SignatureMethod"]]
    elif "SignatureMethod" in body_params and body_params["SignatureMethod"] in SIGN_METHODS:
        signer = SIGN_METHODS[header["SignatureMethod"]]
    elif "SignatureMethod" in header and header["SignatureMethod"] in SIGN_METHODS:
        signer = SIGN_METHODS[header["SignatureMethod"]]
    url_params = __refresh_sign_parameters(params, ak, accept_format, signer)
    signer = SIGN_METHODS[url_params["SignatureMethod"]]
    sign_params = dict(url_params)
    sign_params.update(body_params)
    sign_params = __update_sign_params(sign_params)
    string_to_sign = __compose_string_to_sign(method, sign_params)
    signature = __get_signature(string_to_sign, secret, signer)
    url_params['Signature'] = signature
    url_params = __update_sign_params(url_params)
    url = '/?' + __pop_standard_urlencode(urlencode(url_params))
    return url, string_to_sign, dict(url_params), signature

def __param_to_string(v):
    if v is None:
        return None
    if type(v).__name__ == 'dict':
        sorted_parameters = sorted(iteritems(v), key=lambda queries: queries[0])
        res = "{"
        for k in sorted_parameters:
            itemV = __param_to_string(k[1])
            if itemV is not None:
                res += "\"" + k[0] + "\"" + ":\"" + __param_to_string(k[1]) + "\","
        if len(res) == 1:
            return res+"}"
        return res[:-1] + "}"
    elif type(v).__name__ == 'list':
        res = "["
        for sv in v:
            itemV = __param_to_string(sv)
            if itemV is not None:
                res += "\"" + __param_to_string(sv) + "\","
        if len(res) == 1:
            return res+"]"
        return res[:-1] + "]"
    else:
        return v

def __update_sign_params(params):
    result = dict()
    for key, value in params.items():
        # for nodejs asapi signature compatibility
        if value is None:
            continue
        if type(value).__name__ == 'dict':
            result[key] = __param_to_string(value)
        elif type(value).__name__ == 'list':
            for i in range(len(value)):
                result[key + '.' + str(i + 1)] = __param_to_string(value[i])
        elif type(value).__name__ == 'bool':
            result[key] = str(value).lower()
        else:
            result[key] = value
    return result
