#!/usr/bin/awk -f

BEGIN {
	FS = "\t"
	OFS = "\t"

	BACnetUnconfirmedServiceChoice[0] = "i-Am"
	BACnetUnconfirmedServiceChoice[1] = "i-Have"
	BACnetUnconfirmedServiceChoice[2] = "unconfirmedCOVNotification"
	BACnetUnconfirmedServiceChoice[3] = "unconfirmedEventNotification"
	BACnetUnconfirmedServiceChoice[4] = "unconfirmedPrivateTransfer"
	BACnetUnconfirmedServiceChoice[5] = "unconfirmedTextMessage"
	BACnetUnconfirmedServiceChoice[6] = "timeSynchronization"
	BACnetUnconfirmedServiceChoice[7] = "who-Has"
	BACnetUnconfirmedServiceChoice[8] = "who-Is"
	BACnetUnconfirmedServiceChoice[9] = "utcTimeSynchronization"
	BACnetUnconfirmedServiceChoice[10] = "writeGroup"
	BACnetUnconfirmedServiceChoice[11] = "unconfirmedCovNotificationMultiple"
	BACnetUnconfirmedServiceChoice[12] = "unconfirmedAuditNotification"

	BACnetConfirmedServiceChoice[0] = "acknowledgeAlarm"
	BACnetConfirmedServiceChoice[1] = "confirmedCOVNotification"
	BACnetConfirmedServiceChoice[2] = "confirmedEventNotification"
	BACnetConfirmedServiceChoice[3] = "getAlarmSummary"
	BACnetConfirmedServiceChoice[4] = "getEnrollmentSummary"
	BACnetConfirmedServiceChoice[5] = "subscribeCOV"
	BACnetConfirmedServiceChoice[6] = "atomicReadFile"
	BACnetConfirmedServiceChoice[7] = "atomicWriteFile"
	BACnetConfirmedServiceChoice[8] = "addListElement"
	BACnetConfirmedServiceChoice[9] = "removeListElement"
	BACnetConfirmedServiceChoice[10] = "createObject"
	BACnetConfirmedServiceChoice[11] = "deleteObject"
	BACnetConfirmedServiceChoice[12] = "readProperty"
	BACnetConfirmedServiceChoice[13] = "readPropertyConditional"
	BACnetConfirmedServiceChoice[14] = "readPropertyMultiple"
	BACnetConfirmedServiceChoice[15] = "writeProperty"
	BACnetConfirmedServiceChoice[16] = "writePropertyMultiple"
	BACnetConfirmedServiceChoice[17] = "deviceCommunicationControl"
	BACnetConfirmedServiceChoice[18] = "confirmedPrivateTransfer"
	BACnetConfirmedServiceChoice[19] = "confirmedTextMessage"
	BACnetConfirmedServiceChoice[20] = "reinitializeDevice"
	BACnetConfirmedServiceChoice[21] = "vtOpen"
	BACnetConfirmedServiceChoice[22] = "vtClose"
	BACnetConfirmedServiceChoice[23] = "vtData"
	BACnetConfirmedServiceChoice[24] = "authenticate"
	BACnetConfirmedServiceChoice[25] = "requestKey"
	BACnetConfirmedServiceChoice[26] = "readRange"
	BACnetConfirmedServiceChoice[27] = "lifeSafetyOperation"
	BACnetConfirmedServiceChoice[28] = "subscribeCOVProperty"
	BACnetConfirmedServiceChoice[29] = "getEventInformation"
	BACnetConfirmedServiceChoice[30] = "subscribeCovPropertyMultiple"
	BACnetConfirmedServiceChoice[31] = "confirmedCovNotificationMultiple"
	BACnetConfirmedServiceChoice[32] = "confirmedAuditNotification"
	BACnetConfirmedServiceChoice[33] = "auditLogQuery"

	BACnetTypeName[0] = "Confirmed-REQ"
	BACnetTypeName[1] = "Unconfirmed-REQ"
	BACnetTypeName[2] = "Simple-ACK"
	BACnetTypeName[3] = "Complex-ACK"
	BACnetTypeName[4] = "Segment-ACK"
	BACnetTypeName[5] = "Error"
	BACnetTypeName[6] = "Reject"
	BACnetTypeName[7] = "Abort"

	BACnetObjectType[0] = "analog-input"
	BACnetObjectType[1] = "analog-output"
	BACnetObjectType[2] = "analog-value"
	BACnetObjectType[3] = "binary-input"
	BACnetObjectType[4] = "binary-output"
	BACnetObjectType[5] = "binary-value"
	BACnetObjectType[6] = "calendar"
	BACnetObjectType[7] = "command"
	BACnetObjectType[8] = "device"
	BACnetObjectType[9] = "event-enrollment"
	BACnetObjectType[10] = "file"
	BACnetObjectType[11] = "group"
	BACnetObjectType[12] = "loop"
	BACnetObjectType[13] = "multi-state-input"
	BACnetObjectType[14] = "multi-state-output"
	BACnetObjectType[15] = "notification-class"
	BACnetObjectType[16] = "program"
	BACnetObjectType[17] = "schedule"
	BACnetObjectType[18] = "averaging"
	BACnetObjectType[19] = "multi-state-value"
	BACnetObjectType[20] = "trend-log"
	BACnetObjectType[21] = "life-safety-point"
	BACnetObjectType[22] = "life-safety-zone"
	BACnetObjectType[23] = "accumulator"
	BACnetObjectType[24] = "pulse-converter"
	BACnetObjectType[25] = "event-log"
	BACnetObjectType[26] = "global-group"
	BACnetObjectType[27] = "trend-log-multiple"
	BACnetObjectType[28] = "load-control"
	BACnetObjectType[29] = "structured-view"
	BACnetObjectType[30] = "access-door"
	BACnetObjectType[31] = "timer"
	BACnetObjectType[32] = "access-credential"
	BACnetObjectType[33] = "access-point"
	BACnetObjectType[34] = "access-rights"
	BACnetObjectType[35] = "access-user"
	BACnetObjectType[36] = "access-zone"
	BACnetObjectType[37] = "credential-data-input"
	BACnetObjectType[38] = "network-security"
	BACnetObjectType[39] = "bitstring-value"
	BACnetObjectType[40] = "characterstring-value"
	BACnetObjectType[41] = "date-pattern-value"
	BACnetObjectType[42] = "date-value"
	BACnetObjectType[43] = "datetime-pattern-value"
	BACnetObjectType[44] = "datetime-value"
	BACnetObjectType[45] = "integer-value"
	BACnetObjectType[46] = "large-analog-value"
	BACnetObjectType[47] = "octetstring-value"
	BACnetObjectType[48] = "positive-integer-value"
	BACnetObjectType[49] = "time-pattern-value"
	BACnetObjectType[50] = "time-value"
	BACnetObjectType[51] = "notification-forwarder"
	BACnetObjectType[52] = "alert-enrollment"
	BACnetObjectType[53] = "channel"
	BACnetObjectType[54] = "lighting-output"
	BACnetObjectType[55] = "reserved-obj-type-55"
	BACnetObjectType[56] = "network-port"
	BACnetObjectType[57] = "elevator-group"
	BACnetObjectType[58] = "escalator"
	BACnetObjectType[59] = "lift"
	BACnetObjectType[60] = "staging"
	BACnetObjectType[61] = "audit-log"
	BACnetObjectType[62] = "audit-reporter"

	print("#ts", "src", "dst", "resp_p", "cmd", "apdutype", "objtype")
}
{
	if (NF != 10) {
		next;
	}

	timestamp = $1

	if (length($2) != 0 && length($3) != 0) {
		ip_src = $2
		ip_dst = $3

	} else if (length($4) != 0 && length($5) != 0) {
		ip_src = $4
		ip_dst = $5

	} else {
		next
	}

	udp_dstport = $6

	bacapp_type = $7
	bacapp_confirmed_service = $8
	bacapp_unconfirmed_service = $9

	if (bacapp_type == 0 || bacapp_type == 3) {
		service = BACnetConfirmedServiceChoice[bacapp_confirmed_service] " ("bacapp_confirmed_service")"

	} else if (bacapp_type == 1) {
		service = BACnetUnconfirmedServiceChoice[bacapp_unconfirmed_service] " ("bacapp_unconfirmed_service")"

	} else {
		next

	}

	if (length($10) == 0) {
		bacapp_objectType = "None"
		print(timestamp, ip_src, ip_dst, service, udp_dstport, BACnetTypeName[bacapp_type] " (" bacapp_type ")", bacapp_objectType)
		next
	} else {
		bacapp_objectType = $10
	}

	split(bacapp_objectType, object_list, ",")
	
	#split("", object_hash)
	#for (i = 1; i <= length(object_list); i++ ) {
	#	object_hash[object_list[i]] = 0
	#}


	n = asort(object_list)

	if (object_list[1] < 128) {
		object_str = BACnetObjectType[object_list[1]]
	} else {
		object_str = "(" object_list[1] ") Vendor Proprietary Value"
	}
	print(timestamp, ip_src, ip_dst, service, udp_dstport, BACnetTypeName[bacapp_type] " (" bacapp_type ")", object_str)

	for (i = 2; i <= n; i++) {
		if (object_list[i-1] != object_list[i]) {
			if (object_list[i] < 128) {
				object_str = BACnetObjectType[object_list[i]]
			} else {
				object_str = "(" object_list[i] ") Vendor Proprietary Value"
			}
			print(timestamp, ip_src, ip_dst, service, udp_dstport, BACnetTypeName[bacapp_type] " (" bacapp_type ")", object_str)
		}

	}
}


END {

}

