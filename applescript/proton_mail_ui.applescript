use framework "Foundation"
use scripting additions

property bundleIdentifier : "ch.protonmail.desktop"
property processName : "Proton Mail"
property protocolVersion : 1
property maximumElements : 5000
property pollIntervalSeconds : 0.2
property openTimeoutSeconds : 15
property candidateIdentityTimeoutSeconds : 1
property postconditionTimeoutSeconds : 12
property attachmentDetailsTimeoutSeconds : 3

on run
    try
        set requestObject to my readRequest()
        set requestVersion to my requiredInteger(requestObject, "version")
        if requestVersion is not protocolVersion then my raiseAdapterError(1701)
        set operationName to my requiredText(requestObject, "operation")
        if operationName is "health" then
            my requireExactKeys(requestObject, {"version", "operation"})
            return my encodeResponse(my healthResponse())
        else if operationName is "open_draft" then
            my requireExactKeys(requestObject, {"version", "operation", "internal_id", "row_subject"})
            my openDraft(requestObject)
            return my encodeResponse(my successResponse(missing value))
        else if operationName is "confirm_and_send" then
            my requireExactKeys(requestObject, {"version", "operation", "internal_id", "expires_at_millis", "from", "to", "cc", "bcc", "subject", "body", "attachment_names"})
            set outcomeName to my confirmAndSend(requestObject)
            set factsObject to current application's NSMutableDictionary's dictionary()
            factsObject's setObject:outcomeName forKey:"outcome"
            return my encodeResponse(my successResponse(factsObject))
        else
            my raiseAdapterError(1701)
        end if
    on error errorMessage number errorNumber
        return my encodeResponse(my failureResponse(my stableCode(errorNumber)))
    end try
end run

on readRequest()
    set inputData to current application's NSFileHandle's fileHandleWithStandardInput()'s readDataToEndOfFile()
    if (inputData's |length|() as integer) is 0 then my raiseAdapterError(1701)
    if (inputData's |length|() as integer) > 2097152 then my raiseAdapterError(1701)
    set requestObject to current application's NSJSONSerialization's JSONObjectWithData:inputData options:0 |error|:(missing value)
    if requestObject is missing value then my raiseAdapterError(1701)
    if (requestObject's isKindOfClass:(current application's NSDictionary)) as boolean is false then my raiseAdapterError(1701)
    return requestObject
end readRequest

on encodeResponse(responseObject)
    set responseData to current application's NSJSONSerialization's dataWithJSONObject:responseObject options:0 |error|:(missing value)
    if responseData is missing value then return "{\"version\":1,\"status\":\"error\",\"code\":\"internal\"}"
    set responseText to current application's NSString's alloc()'s initWithData:responseData encoding:(current application's NSUTF8StringEncoding)
    return responseText as text
end encodeResponse

on successResponse(factsObject)
    set responseObject to current application's NSMutableDictionary's dictionary()
    responseObject's setObject:protocolVersion forKey:"version"
    responseObject's setObject:"ok" forKey:"status"
    if factsObject is not missing value then responseObject's setObject:factsObject forKey:"facts"
    return responseObject
end successResponse

on failureResponse(codeName)
    set responseObject to current application's NSMutableDictionary's dictionary()
    responseObject's setObject:protocolVersion forKey:"version"
    responseObject's setObject:"error" forKey:"status"
    responseObject's setObject:codeName forKey:"code"
    return responseObject
end failureResponse

on healthResponse()
    set factsObject to current application's NSMutableDictionary's dictionary()
    set workspaceObject to current application's NSWorkspace's sharedWorkspace()
    set applicationURL to workspaceObject's URLForApplicationWithBundleIdentifier:bundleIdentifier
    set installedValue to applicationURL is not missing value
    set runningValue to false
    set accessibilityValue to false
    set probeValue to false
    set versionValue to missing value
    if installedValue then
        set bundleObject to current application's NSBundle's bundleWithURL:applicationURL
        set versionObject to bundleObject's objectForInfoDictionaryKey:"CFBundleShortVersionString"
        if versionObject is not missing value then set versionValue to versionObject as text
    end if
    tell application "System Events"
        set accessibilityValue to UI elements enabled
        set matchingProcesses to every application process whose bundle identifier is bundleIdentifier
        if (count of matchingProcesses) is 1 then set runningValue to true
    end tell
    if runningValue and accessibilityValue then
        -- Permission and UI capability are separate facts; ambiguity is a failed probe.
        try
            set targetWindow to my oneMainWindow(false)
            set allItems to my boundedContents(targetWindow)
            repeat with candidate in allItems
                if my safeRole(candidate) is "AXWebArea" then
                    set probeValue to true
                    exit repeat
                end if
            end repeat
        on error errorMessage number errorNumber
            if errorNumber is not 1702 then
                if errorNumber is not 1703 then error errorMessage number errorNumber
            end if
            set probeValue to false
        end try
    end if
    factsObject's setObject:installedValue forKey:"application_installed"
    factsObject's setObject:runningValue forKey:"application_running"
    factsObject's setObject:accessibilityValue forKey:"accessibility_authorized"
    factsObject's setObject:probeValue forKey:"capability_probe_passed"
    if versionValue is not missing value then factsObject's setObject:versionValue forKey:"application_version"
    return my successResponse(factsObject)
end healthResponse

on openDraft(requestObject)
    set internalIdentifier to my requiredText(requestObject, "internal_id")
    if (length of internalIdentifier) > 512 or internalIdentifier contains "/" or internalIdentifier contains return or internalIdentifier contains linefeed then my raiseAdapterError(1701)
    set subjectText to my canonicalText(my requiredText(requestObject, "row_subject"))
    my ensureApplicationReady()
    set deadlineDate to (current date) + openTimeoutSeconds
    set candidatePosition to 1
    repeat while (current date) < deadlineDate
        set targetWindow to my oneMainWindow(true)
        set draftLink to my oneElement(targetWindow, "AXLink", "Drafts", false)
        my pressElement(draftLink)
        set candidates to my draftCandidates(subjectText)
        if (count of candidates) ≥ candidatePosition then
            set candidateRow to item candidatePosition of candidates
            my pressElement(candidateRow)
            set candidateDeadlineDate to (current date) + candidateIdentityTimeoutSeconds
            if candidateDeadlineDate > deadlineDate then set candidateDeadlineDate to deadlineDate
            if my waitForInternalIdentifier(internalIdentifier, candidateDeadlineDate) then
                my waitForComposer(deadlineDate)
                return
            end if
            set candidatePosition to candidatePosition + 1
        end if
        delay pollIntervalSeconds
    end repeat
    my raiseAdapterError(1704)
end openDraft

on confirmAndSend(requestObject)
    set expiryMilliseconds to my requiredInteger(requestObject, "expires_at_millis")
    set currentMilliseconds to ((current application's NSDate's date()'s timeIntervalSince1970()) * 1000) as integer
    if currentMilliseconds ≥ expiryMilliseconds then my raiseAdapterError(1705)
    my verifyComposer(requestObject)
    try
        set dialogResult to display dialog "Send this verified Proton Mail draft now?" buttons {"Cancel", "Send"} default button "Cancel" with icon caution giving up after 120
    on error number errorNumber
        if errorNumber is -128 then return "cancelled"
        my raiseAdapterError(1703)
    end try
    if gave up of dialogResult then return "cancelled"
    if button returned of dialogResult is not "Send" then return "cancelled"
    set currentMilliseconds to ((current application's NSDate's date()'s timeIntervalSince1970()) * 1000) as integer
    if currentMilliseconds ≥ expiryMilliseconds then my raiseAdapterError(1705)
    set sendButton to my verifyComposer(requestObject)
    try
        my pressElement(sendButton)
    on error
        my raiseAdapterError(1706)
    end try
    set deadlineDate to (current date) + postconditionTimeoutSeconds
    repeat while (current date) < deadlineDate
        try
            if my composerStillOpen(requestObject) is false then return "sent"
        on error
            my raiseAdapterError(1706)
        end try
        delay pollIntervalSeconds
    end repeat
    my raiseAdapterError(1706)
end confirmAndSend

on verifyComposer(requestObject)
    set internalIdentifier to my requiredText(requestObject, "internal_id")
    set expectedFrom to my requiredText(requestObject, "from")
    set expectedSubject to my requiredText(requestObject, "subject")
    set expectedBody to my requiredText(requestObject, "body")
    set expectedTo to my requiredTextList(requestObject, "to")
    set expectedCc to my requiredTextList(requestObject, "cc")
    set expectedBcc to my requiredTextList(requestObject, "bcc")
    set expectedAttachments to my requiredTextList(requestObject, "attachment_names")
    set targetWindow to my oneMainWindow(true)
    if my windowContainsIdentifier(targetWindow, internalIdentifier) is false then my raiseAdapterError(1705)
    set sendButton to my oneElement(targetWindow, "AXButton", "Send", true)
    if my safeEnabled(sendButton) is false then my raiseAdapterError(1705)
    set composerRoot to my composerRootFor(sendButton)
    set composerItems to my boundedContents(composerRoot)
    set subjectField to my oneElementFromList(composerItems, "AXTextField", "Subject", false)
    set visibleSubject to my canonicalText(my safeValue(subjectField))
    set expectedCanonicalSubject to my canonicalText(expectedSubject)
    if visibleSubject is not expectedCanonicalSubject then my raiseAdapterError(1705)
    my oneElementFromList(composerItems, "AXButton", expectedFrom, false)
    my verifyRecipients(composerItems, expectedTo, expectedCc, expectedBcc)
    my verifyAttachments(composerRoot, expectedAttachments)
    set bodyArea to my oneRoleFromList(composerItems, "AXTextArea")
    set visibleBody to my normalizedText(my safeValue(bodyArea))
    set expectedNormalizedBody to my normalizedText(expectedBody)
    if visibleBody is not expectedNormalizedBody then my raiseAdapterError(1705)
    return sendButton
end verifyComposer

on composerStillOpen(requestObject)
    set targetWindow to my oneMainWindow(true)
    set internalIdentifier to my requiredText(requestObject, "internal_id")
    return my windowContainsIdentifier(targetWindow, internalIdentifier)
end composerStillOpen

on verifyRecipients(composerItems, expectedTo, expectedCc, expectedBcc)
    set expectedCombined to expectedTo & expectedCc & expectedBcc
    set observedAddresses to {}
    repeat with candidate in composerItems
        if my safeRole(candidate) is "AXButton" then
            set helpText to my safeHelp(candidate)
            if my looksLikeEmail(helpText) then set end of observedAddresses to helpText
        end if
    end repeat
    if my sameTextMultiset(observedAddresses, expectedCombined) is false then my raiseAdapterError(1705)
    repeat with addressText in expectedTo
        if my recipientHasLabel(composerItems, addressText as text, "to") is false then my raiseAdapterError(1705)
    end repeat
    repeat with addressText in expectedCc
        if my recipientHasLabel(composerItems, addressText as text, "cc") is false then my raiseAdapterError(1705)
    end repeat
    repeat with addressText in expectedBcc
        if my recipientHasLabel(composerItems, addressText as text, "bcc") is false then my raiseAdapterError(1705)
    end repeat
end verifyRecipients

on recipientHasLabel(composerItems, addressText, expectedLabel)
    repeat with candidate in composerItems
        if my safeRole(candidate) is "AXButton" and my safeHelp(candidate) is addressText then
            set labelText to my lowercaseText(my elementLabel(candidate))
            if labelText starts with expectedLabel & " " then return true
        end if
    end repeat
    return false
end recipientHasLabel

on verifyAttachments(composerRoot, expectedAttachments)
    set composerItems to my boundedContents(composerRoot)
    set summaryButtons to my attachmentSummaryButtons(composerItems)
    set observedAttachments to my attachmentNames(composerItems)
    if (count of expectedAttachments) is 0 then
        if (count of summaryButtons) is not 0 or (count of observedAttachments) is not 0 then my raiseAdapterError(1705)
        return
    end if
    if (count of summaryButtons) is not 1 then my raiseAdapterError(1705)
    set summaryButton to item 1 of summaryButtons
    set summaryHelp to my safeHelp(summaryButton)
    if summaryHelp is "Show attachment details" then
        my pressElement(summaryButton)
    else if summaryHelp is not "Hide attachment details" then
        my raiseAdapterError(1705)
    end if
    set deadlineDate to (current date) + attachmentDetailsTimeoutSeconds
    repeat while (current date) < deadlineDate
        set observedAttachments to my attachmentNames(my boundedContents(composerRoot))
        if my sameTextMultiset(observedAttachments, expectedAttachments) then return
        delay pollIntervalSeconds
    end repeat
    my raiseAdapterError(1705)
end verifyAttachments

on attachmentSummaryButtons(composerItems)
    set matchingButtons to {}
    repeat with candidate in composerItems
        if my safeRole(candidate) is "AXButton" then
            set helpText to my safeHelp(candidate)
            if helpText is "Show attachment details" or helpText is "Hide attachment details" then set end of matchingButtons to candidate
        end if
    end repeat
    return matchingButtons
end attachmentSummaryButtons

on attachmentNames(composerItems)
    set observedNames to {}
    repeat with candidate in composerItems
        if my safeRole(candidate) is "AXButton" then
            set candidateLabel to my elementLabel(candidate)
            if candidateLabel starts with "Remove " and (length of candidateLabel) > 7 then
                set end of observedNames to text 8 thru -1 of candidateLabel
            end if
        end if
    end repeat
    return observedNames
end attachmentNames

on composerRootFor(sendButton)
    set currentElement to sendButton
    repeat 6 times
        set parentElement to my safeParent(currentElement)
        if parentElement is missing value then exit repeat
        set parentItems to my boundedContents(parentElement)
        set hasSubject to my listHasElement(parentItems, "AXTextField", "Subject")
        set hasBody to my listHasRole(parentItems, "AXTextArea")
        if hasSubject and hasBody then return parentElement
        set currentElement to parentElement
    end repeat
    my raiseAdapterError(1703)
end composerRootFor

on draftCandidates(subjectText)
    set targetWindow to my oneMainWindow(true)
    set allItems to my boundedContents(targetWindow)
    set candidates to {}
    set fallbackRows to {}
    repeat with candidate in allItems
        if my safeRole(candidate) is "AXHeading" then
            set candidateSubject to my canonicalText(my elementLabel(candidate))
            set rowElement to my safeParent(candidate)
            if rowElement is not missing value then
                set rowItems to my boundedContents(rowElement)
                if my listHasRole(rowItems, "AXCheckBox") then
                    if subjectText is "" and (count of fallbackRows) < 20 then set end of fallbackRows to rowElement
                    if my subjectMatches(subjectText, candidateSubject) then set end of candidates to rowElement
                end if
            end if
        end if
        if (count of candidates) ≥ 20 then exit repeat
    end repeat
    -- Empty subjects may use a version-sensitive non-empty placeholder. If no
    -- stable label match exists, retain a bounded list for identity probing;
    -- openDraft must verify the exact internal ID before accepting a row.
    if subjectText is "" and (count of candidates) is 0 then return fallbackRows
    return candidates
end draftCandidates

on subjectMatches(subjectText, candidateSubject)
    if candidateSubject is subjectText then return true
    if candidateSubject is "" then return false

    set prefixText to candidateSubject
    if candidateSubject ends with "..." then
        if (length of candidateSubject) ≤ 3 then return false
        set prefixText to text 1 thru ((length of candidateSubject) - 3) of candidateSubject
    else if candidateSubject ends with "…" then
        if (length of candidateSubject) ≤ 1 then return false
        set prefixText to text 1 thru ((length of candidateSubject) - 1) of candidateSubject
    end if
    if prefixText is "" then return false

    return subjectText begins with prefixText
end subjectMatches

on waitForInternalIdentifier(internalIdentifier, deadlineDate)
    repeat while (current date) < deadlineDate
        set targetWindow to my oneMainWindow(true)
        if my windowContainsIdentifier(targetWindow, internalIdentifier) then return true
        delay pollIntervalSeconds
    end repeat
    return false
end waitForInternalIdentifier

on waitForComposer(deadlineDate)
    repeat while (current date) < deadlineDate
        set targetWindow to my oneMainWindow(true)
        try
            set sendButton to my oneElement(targetWindow, "AXButton", "Send", true)
            if sendButton is not missing value then return
        end try
        delay pollIntervalSeconds
    end repeat
    my raiseAdapterError(1703)
end waitForComposer

on windowContainsIdentifier(targetWindow, internalIdentifier)
    set allItems to my boundedContents(targetWindow)
    repeat with candidate in allItems
        if my safeRole(candidate) is "AXWebArea" then
            set urlText to my safeAttribute(candidate, "AXURL")
            set identifierSegment to "/" & internalIdentifier
            if urlText ends with identifierSegment then return true
            if urlText contains (identifierSegment & "/") then return true
            if urlText contains (identifierSegment & "?") then return true
            if urlText contains (identifierSegment & "#") then return true
        end if
    end repeat
    return false
end windowContainsIdentifier

on ensureApplicationReady()
    set workspaceObject to current application's NSWorkspace's sharedWorkspace()
    set applicationURL to workspaceObject's URLForApplicationWithBundleIdentifier:bundleIdentifier
    if applicationURL is missing value then my raiseAdapterError(1703)
    set openedApplication to workspaceObject's openURL:applicationURL
    if openedApplication as boolean is false then my raiseAdapterError(1703)
    set deadlineDate to (current date) + 10
    repeat while (current date) < deadlineDate
        tell application "System Events"
            if UI elements enabled then
                set matchingProcesses to every application process whose bundle identifier is bundleIdentifier
                if (count of matchingProcesses) is 1 then return
            else
                my raiseAdapterError(1702)
            end if
        end tell
        delay pollIntervalSeconds
    end repeat
    my raiseAdapterError(1703)
end ensureApplicationReady

on oneMainWindow(raiseWindow)
    tell application "System Events"
        if UI elements enabled is false then my raiseAdapterError(1702)
        set matchingProcesses to every application process whose bundle identifier is bundleIdentifier
        if (count of matchingProcesses) is not 1 then my raiseAdapterError(1703)
        set targetProcess to item 1 of matchingProcesses
        set matchingWindows to every window of targetProcess whose subrole is "AXStandardWindow"
        if (count of matchingWindows) is not 1 then my raiseAdapterError(1703)
        set targetWindow to item 1 of matchingWindows
        if raiseWindow then
            set frontmost of targetProcess to true
            perform action "AXRaise" of targetWindow
        end if
        return targetWindow
    end tell
end oneMainWindow

on boundedContents(rootElement)
    tell application "System Events" to set allItems to entire contents of rootElement
    if (count of allItems) > maximumElements then my raiseAdapterError(1703)
    return allItems
end boundedContents

on oneElement(rootElement, roleName, labelText, requireEnabled)
    return my oneElementFromList(my boundedContents(rootElement), roleName, labelText, requireEnabled)
end oneElement

on oneElementFromList(allItems, roleName, labelText, requireEnabled)
    set matchesList to {}
    repeat with candidate in allItems
        if my safeRole(candidate) is roleName and my elementLabel(candidate) is labelText then
            if requireEnabled is false or my safeEnabled(candidate) then set end of matchesList to candidate
        end if
    end repeat
    if (count of matchesList) is not 1 then my raiseAdapterError(1703)
    return item 1 of matchesList
end oneElementFromList

on oneRoleFromList(allItems, roleName)
    set matchesList to {}
    repeat with candidate in allItems
        if my safeRole(candidate) is roleName then set end of matchesList to candidate
    end repeat
    if (count of matchesList) is not 1 then my raiseAdapterError(1703)
    return item 1 of matchesList
end oneRoleFromList

on listHasElement(allItems, roleName, labelText)
    repeat with candidate in allItems
        if my safeRole(candidate) is roleName and my elementLabel(candidate) is labelText then return true
    end repeat
    return false
end listHasElement

on listHasRole(allItems, roleName)
    repeat with candidate in allItems
        if my safeRole(candidate) is roleName then return true
    end repeat
    return false
end listHasRole

on pressElement(targetElement)
    tell application "System Events"
        if enabled of targetElement is false then my raiseAdapterError(1703)
        perform action "AXPress" of targetElement
    end tell
end pressElement

on requiredText(dictionaryObject, keyName)
    set valueObject to dictionaryObject's objectForKey:keyName
    if valueObject is missing value then my raiseAdapterError(1701)
    if (valueObject's isKindOfClass:(current application's NSString)) as boolean is false then my raiseAdapterError(1701)
    set valueText to valueObject as text
    if (length of valueText) > 1048576 then my raiseAdapterError(1701)
    return valueText
end requiredText

on requiredInteger(dictionaryObject, keyName)
    set valueObject to dictionaryObject's objectForKey:keyName
    if valueObject is missing value then my raiseAdapterError(1701)
    if (valueObject's isKindOfClass:(current application's NSNumber)) as boolean is false then my raiseAdapterError(1701)
    return valueObject as integer
end requiredInteger

on requiredTextList(dictionaryObject, keyName)
    set valueObject to dictionaryObject's objectForKey:keyName
    if valueObject is missing value then my raiseAdapterError(1701)
    if (valueObject's isKindOfClass:(current application's NSArray)) as boolean is false then my raiseAdapterError(1701)
    if (valueObject's |count|() as integer) > 50 then my raiseAdapterError(1701)
    set resultList to {}
    repeat with valueItem in (valueObject as list)
        if (valueItem's isKindOfClass:(current application's NSString)) as boolean is false then my raiseAdapterError(1701)
        set valueText to valueItem as text
        if (length of valueText) > 4096 then my raiseAdapterError(1701)
        set end of resultList to valueText
    end repeat
    return resultList
end requiredTextList

on requireExactKeys(dictionaryObject, allowedKeys)
    set observedKeys to dictionaryObject's allKeys() as list
    if (count of observedKeys) is not (count of allowedKeys) then my raiseAdapterError(1701)
    repeat with observedKey in observedKeys
        set keyText to observedKey as text
        if allowedKeys does not contain keyText then my raiseAdapterError(1701)
    end repeat
end requireExactKeys

on safeRole(targetElement)
    try
        tell application "System Events" to return role of targetElement as text
    on error
        return ""
    end try
end safeRole

on safeValue(targetElement)
    try
        tell application "System Events" to return value of targetElement as text
    on error
        return ""
    end try
end safeValue

on safeHelp(targetElement)
    try
        tell application "System Events" to return help of targetElement as text
    on error
        return ""
    end try
end safeHelp

on safeEnabled(targetElement)
    try
        tell application "System Events" to return enabled of targetElement
    on error
        return false
    end try
end safeEnabled

on safeParent(targetElement)
    try
        tell application "System Events" to return value of attribute "AXParent" of targetElement
    on error
        return missing value
    end try
end safeParent

on safeAttribute(targetElement, attributeName)
    try
        tell application "System Events" to return value of attribute attributeName of targetElement as text
    on error
        return ""
    end try
end safeAttribute

on elementLabel(targetElement)
    try
        tell application "System Events" to set descriptionText to description of targetElement as text
        if descriptionText is not "" then return descriptionText
    end try
    try
        tell application "System Events" to set nameText to name of targetElement as text
        if nameText is not "" then return nameText
    end try
    return my safeValue(targetElement)
end elementLabel

on looksLikeEmail(valueText)
    if valueText does not contain "@" then return false
    if valueText contains " " or valueText contains return or valueText contains linefeed then return false
    return true
end looksLikeEmail

on sameTextMultiset(leftList, rightList)
    if (count of leftList) is not (count of rightList) then return false
    set remainingValues to rightList
    repeat with leftValue in leftList
        set canonicalLeftValue to my canonicalText(leftValue as text)
        set foundPosition to 0
        repeat with positionValue from 1 to (count of remainingValues)
            set canonicalRightValue to my canonicalText((item positionValue of remainingValues) as text)
            if canonicalRightValue is canonicalLeftValue then
                set foundPosition to positionValue
                exit repeat
            end if
        end repeat
        if foundPosition is 0 then return false
        if (count of remainingValues) is 1 then
            set remainingValues to {}
        else if foundPosition is 1 then
            set remainingValues to items 2 thru -1 of remainingValues
        else if foundPosition is (count of remainingValues) then
            set remainingValues to items 1 thru -2 of remainingValues
        else
            set remainingValues to (items 1 thru (foundPosition - 1) of remainingValues) & (items (foundPosition + 1) thru -1 of remainingValues)
        end if
    end repeat
    return (count of remainingValues) is 0
end sameTextMultiset

on normalizedText(valueText)
    set foundationText to current application's NSMutableString's stringWithString:valueText
    set crlfText to return & linefeed
    foundationText's replaceOccurrencesOfString:crlfText withString:linefeed options:0 range:{location:0, |length|:foundationText's |length|()}
    foundationText's replaceOccurrencesOfString:return withString:linefeed options:0 range:{location:0, |length|:foundationText's |length|()}
    return (foundationText's precomposedStringWithCanonicalMapping()) as text
end normalizedText

on canonicalText(valueText)
    return ((current application's NSString's stringWithString:valueText)'s precomposedStringWithCanonicalMapping()) as text
end canonicalText

on lowercaseText(valueText)
    return (current application's NSString's stringWithString:valueText)'s lowercaseString() as text
end lowercaseText

on stableCode(errorNumber)
    if errorNumber is 1701 then return "validation_failed"
    if errorNumber is 1702 or errorNumber is -25211 or errorNumber is -1743 then return "permission_denied"
    if errorNumber is 1703 then return "ambiguous_ui"
    if errorNumber is 1704 then return "not_found"
    if errorNumber is 1705 then return "conflict"
    if errorNumber is 1706 then return "send_unknown"
    if errorNumber is -128 then return "cancelled"
    return "ui_unavailable"
end stableCode

on raiseAdapterError(errorNumber)
    error "Proton Mail UI adapter failed" number errorNumber
end raiseAdapterError
