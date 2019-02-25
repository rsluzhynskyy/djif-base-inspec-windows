# Set additional flags to simplify checks management
kitchen = file('C:\Users\vagrant\AppData\Local\Temp\kitchen').exist?
win2016 = os.name.include?('2016')
cis_benchmark = win2016 ? 'cis-windows2016rtm-release1607-level1-memberserver' : 'cis-windows2012r2-level1-memberserver'

include_controls 'windows-baseline' do
  if kitchen
    # Skip these tests during local run, because we need to  be  able
    # to connect with non-administrator WinRM user to perform actions
    skip_control 'cis-network-access-2.2.2'
    skip_control 'windows-account-100'
  end
  # Skip this check because it conflicts with xccdf_org.cisecurity.benchmarks_rule_2.3.11.7_L1
  skip_control 'windows-base-201'
end

include_controls cis_benchmark do
  if kitchen
    # Skip these tests during local run, because we need to  be  able
    # to connect with non-administrator WinRM user to perform actions
    skip_control 'xccdf_org.cisecurity.benchmarks_rule_2.2.2_L1_Configure_Access_this_computer_from_the_network'
    skip_control 'xccdf_org.cisecurity.benchmarks_rule_2.2.7_L1_Configure_Allow_log_on_through_Remote_Desktop_Services'
    # Skip this check because local box doesn't have "PNP Activity" audit entry
    skip_control 'xccdf_org.cisecurity.benchmarks_rule_17.3.1_L1_Ensure_Audit_PNP_Activity_is_set_to_Success'

    unless win2016
      # [2012 only] Skip this check, because it requires WinRM lock on Windows 2012
      skip_control 'xccdf_org.cisecurity.benchmarks_rule_18.6.1_L1_Ensure_Apply_UAC_restrictions_to_local_accounts_on_network_logons_is_set_to_Enabled_MS_only'
    end

    # Modify next 3 controls because Inspec can't manage keys.with.periods,
    # changed  its('string')  to  its(['string'])  (put  string  to  array)
    # https://github.com/inspec/inspec/issues/1281
    control 'xccdf_org.cisecurity.benchmarks_rule_18.9.24.3_L1_Ensure_Default_Protections_for_Internet_Explorer_is_set_to_Enabled' do
      describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\Defaults') do
        it { should have_property '*\Internet Explorer\iexplore.exe' }
        its(['*\Internet Explorer\iexplore.exe']) { should eq '+EAF+ eaf_modules:mshtml.dll;flash*.ocx;jscript*.dll;vbscript.dll;vgx.dll +ASR asr_modules:npjpi*.dll;jp2iexp.dll;vgx.dll;msxml4*.dll;wshom.ocx;scrrun.dll;vbscript.dll asr_zones:1;2' }
      end
    end
    control 'xccdf_org.cisecurity.benchmarks_rule_18.9.24.4_L1_Ensure_Default_Protections_for_Popular_Software_is_set_to_Enabled' do
      describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\Defaults') do
        it { should have_property '*\Mozilla Thunderbird\thunderbird.exe' }
        its(['*\Mozilla Thunderbird\thunderbird.exe']) { should match(//) }
      end
    end
    control 'xccdf_org.cisecurity.benchmarks_rule_18.9.24.5_L1_Ensure_Default_Protections_for_Recommended_Software_is_set_to_Enabled' do
      describe registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EMET\Defaults') do
        it { should have_property '*\Java\jre*\bin\javaws.exe' }
        its(['*\Java\jre*\bin\javaws.exe']) { should eq '-HeapSpray' }
      end
    end
  end
end
