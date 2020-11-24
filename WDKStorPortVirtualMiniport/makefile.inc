LNG=$(LANGUAGE)
_INX=.
STAMP=stampinf -n -f $@ -a $(_BUILDARCH) -k $(KMDF_VERSION_MAJOR).$(KMDF_VERSION_MINOR)

$(OBJ_PATH)\$(O)\$(INF_NAME).inf: $(_INX)\$(INF_NAME).inx 
    copy $(_INX)\$(@B).inx $@
    $(STAMP)

$(OBJ_PATH)\$O\hbaapi.mof $(OBJ_PATH)\$O\hbaapi.mfl: hbaapi.mof
## Pre-process .mof file.
    $(C_PREPROCESSOR_NAME) $(C_PREPROCESSOR_FLAGS) hbaapi.mof > $(OBJ_PATH)\$(O)\hbaapi.tmp

## Make a copy, for the mof-compilation step below
    copy $(OBJ_PATH)\$(O)\hbaapi.tmp .\hbaapi.mof

## Compile the base .mof file, which will include the new .mof file.
    mofcomp -WMI -B:$(OBJ_PATH)\$(O)\\mp.bmf mp.mof

## Build mpwmi.h
    wmimofck -h.\inc\mpwmi.h -m -u -w.\html $(OBJ_PATH)\$(O)\mp.bmf
