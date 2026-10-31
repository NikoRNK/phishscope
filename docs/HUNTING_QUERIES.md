# Hunting queries — turning one IOC into a full scope

PhishScope's `blast.py` works on exported messages. In a real SOC you run the
equivalent query inside your tooling. Replace the example indicators with the
values from `iocs.csv`.

## Microsoft Defender XDR — Advanced Hunting (KQL)

**Who received the campaign, and where did it land?**

```kql
EmailEvents
| where Timestamp > ago(14d)
| where SenderFromAddress =~ "no-reply@microsoft.com"
    and SenderMailFromDomain =~ "mail-relay-77.bulkmailer.example"
| project Timestamp, NetworkMessageId, RecipientEmailAddress, Subject,
          DeliveryAction, DeliveryLocation, SenderIPv4
| order by Timestamp asc
```

**Same malicious domain in any URL, regardless of sender:**

```kql
EmailUrlInfo
| where Timestamp > ago(14d)
| where UrlDomain endswith "rnicrosoft-support.example"
| join kind=inner EmailEvents on NetworkMessageId
| project Timestamp, RecipientEmailAddress, Subject, Url, DeliveryAction
```

**Same attachment hash:**

```kql
EmailAttachmentInfo
| where Timestamp > ago(14d) and SHA256 == "d6573e0e82be31b8f167cbe8fc1afb827e664c4750366b53fa138384e237e00a"
| join kind=inner EmailEvents on NetworkMessageId
| project Timestamp, RecipientEmailAddress, FileName, Subject
```

**Who actually clicked?** (requires Safe Links)

```kql
UrlClickEvents
| where Timestamp > ago(14d)
| where Url has "rnicrosoft-support.example"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough
```

## Splunk (SPL) — adapt index/sourcetype/field names to your CIM mapping

```spl
index=email sourcetype=mail_gateway earliest=-14d
  (src_user="no-reply@microsoft.com" AND return_path="*@mail-relay-77.bulkmailer.example")
| stats earliest(_time) AS first_seen latest(_time) AS last_seen values(recipient) AS recipients dc(recipient) AS n by message_subject
```

```spl
index=proxy earliest=-14d (url="*rnicrosoft-support.example*" OR dest_ip=203.0.113.45)
| stats count values(url) AS urls by user src_ip
```

## Exchange Online — contain (compliance search + purge)

```powershell
New-ComplianceSearch -Name "PhishCampaign-PI-A104FFF3" -ExchangeLocation All `
  -ContentMatchQuery 'from:no-reply@microsoft.com AND subject:"password expires"'
Start-ComplianceSearch -Identity "PhishCampaign-PI-A104FFF3"
# review the item count first, then:
New-ComplianceSearchAction -SearchName "PhishCampaign-PI-A104FFF3" -Purge -PurgeType SoftDelete
```

> Always **preview** a compliance search before purging; an over-broad query
> deletes legitimate mail.

## Containment checklist

- [ ] Message purged from all affected mailboxes
- [ ] Sender, Return-Path domain, URLs, IP blocked (gateway / proxy / DNS)
- [ ] Proxy / DNS / EDR hunted for the IOCs over the same time window
- [ ] Credentials reset + sessions revoked for every user who clicked or opened
- [ ] Recipients informed; impersonated brand and hosting abuse contact notified
- [ ] IOCs added to the TIP / SIEM watchlist; case documented
