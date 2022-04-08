#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5200) exit(0, "Not Nessus 5.2+");

include("compat.inc");

if (description)
{
  script_id(999000);
  script_version("0.0.5");
  #script_cvs_date("Date: 2018/07/10 12:08:45");

  script_name(english:"Nessus scan account aging information");
  script_summary(english:"Nessus scan account aging information");

  script_set_attribute(attribute:"synopsis", value:
  "Uses chage -l `whoami` command to obtain nessus scan account aging information on the target machine at scan time.");
  script_set_attribute(attribute:"description", value:
  "Uses chage -l `whoami` command to obtain nessus scan account aging information on the target machine at scan time.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/03/29");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Nessus Manage");
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname", "Host/hostname");

  exit(0);
}

include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("global_settings.inc");
include("misc_func.inc");
include("data_protection.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/uname")) audit(AUDIT_KB_MISSING, "Host/uname");
if (!get_kb_item("Host/hostname")) audit(AUDIT_KB_MISSING, "Host/hostname");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS)
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF,"pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

# Should work on all *nix environments
cmd = "whoami; chage -l `whoami`";
report = info_send_cmd(cmd:cmd);
if (info_t == INFO_SSH) ssh_close_connection();
if (empty_or_null(report))
{
  exit(1, "Account aging information not possible to get.");
}

security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
