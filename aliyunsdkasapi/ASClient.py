from aliyunsdkasapi.client import AcsClient


class ASClient(AcsClient):
    X_ACS_RESOUECEGROUP_ID = "x-acs-resourcegroupid";
    X_ACS_ORGANIZATION_ID = "x-acs-organizationid";
    X_ACS_REGIONID="x-acs-regionid";
    X_ACS_INSTANCEID = "x-acs-instanceid";
    
    def __init__(self, accessKeyId, accessKeySecret, regionId,
            timeout=None,
            cert_file=None,
            verify=None,
            key_file=None):
        self.client = AcsClient.__init__(self,accessKeyId,
                                accessKeySecret,
                                region_id=regionId,
                                auto_retry=True,
                                max_retry_time=3,
                                user_agent=None,
                                port=80,
                                cert_file=cert_file,
                                key_file=key_file,
                                timeout=timeout,
                                verify=verify,
                                debug=True)
            

