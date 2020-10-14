import "androguard"

rule adw_trj+noroxi0
{
  meta:
       description= "スマホ使用中に突然ブラウザを開きMalverstingに誘導する(org.myklos.btautoconnect)"
  condition:
       androguard.activity(/*msdns\.noroxi*/)
}

rule spywr_phish_wrm_trj+fakechrome0
{
  meta:
       description= "自身をChromeに偽装し、フィッシング詐欺に誘導する。ワーム機能を有し、SMSで伝搬する。"
  condition:
       androguard.activity(/*\.MdService/) and
       androguard.receiver(/*\.LoReceiver/i)
}

rule backdr_trj+feckless0
{
  meta:
       description= "主に有料アプリのCrackに見せかけて感染し、攻撃者の任意のコードを実行する"
  condition:
       androguard.app_name("") or
       androguard.app_name("\s") or
       androguard.service(/com\.deflocculent\.fecklessness*/) or
       androguard.service(/*WinklehawkPeckishlyService/)
}
