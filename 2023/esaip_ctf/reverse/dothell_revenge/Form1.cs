using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace dothell
{
	// Token: 0x02000002 RID: 2
	public class Form1 : Form
	{
		// Token: 0x06000004 RID: 4 RVA: 0x00002057 File Offset: 0x00000257
		public Form1()
		{
			this.InitializeComponent();
		}

		// Token: 0x06000005 RID: 5 RVA: 0x00002764 File Offset: 0x00000964
		private void nantendoShadowBan()
		{
			try
			{
				foreach (Process process in Process.GetProcesses())
				{
					if ("dnSpy".Equals(process.ProcessName))
					{
						MessageBox.Show("dnSpy detected");
						base.Close();
					}
					if ("ILSpy".Equals(process.ProcessName))
					{
						MessageBox.Show("ILSpy detected");
						base.Close();
					}
				}
			}
			catch (Exception ex)
			{
				MessageBox.Show(ex.Message);
			}
		}

		// Token: 0x06000006 RID: 6 RVA: 0x000027F0 File Offset: 0x000009F0
		private void checker_Click(object sender, EventArgs e)
		{
			int num = 1;
			int length = this.supplier.Text.Length;
			int num2 = -1;
			while (num == 1)
			{
				if (num2 + 5 > length - 1)
				{
					num = 0;
				}
				else
				{
					num2 += 5;
					if (!this.supplier.Text[num2].Equals(Encoding.UTF8.GetString(Convert.FromBase64String("LQ=="))[0]))
					{
						MessageBox.Show("Not for you!");
						return;
					}
				}
			}
			if (length / 5 + 1 != 8)
			{
				MessageBox.Show("Not for you!");
				return;
			}
			int num3 = 1;
			int num4 = 0;
			int num5 = 0;
			if (num4 > length - 1)
			{
				MessageBox.Show("Not for you!");
				return;
			}
			while (num3 == 1)
			{
				if (!this.supplier.Text[num4].Equals(Convert.ToChar((int)(Encoding.UTF8.GetString(Convert.FromBase64String(this.ichi.Text))[num5] - '\u0014'))))
				{
					MessageBox.Show("Not for you!");
					return;
				}
				if (num4 + 5 > length - 1)
				{
					num3 = 0;
				}
				else
				{
					num4 += 5;
					num5++;
				}
			}
			int num6 = 1;
			num4 = length - 1;
			num5 = 0;
			if (num4 > length - 1)
			{
				MessageBox.Show("Not for you!");
				return;
			}
			while (num6 == 1)
			{
				if (!Convert.ToChar((int)(this.supplier.Text[num4] % '\u007f')).Equals(Convert.ToChar((int)(Encoding.UTF8.GetString(Convert.FromBase64String(this.ni.Text))[num5] - '\u0018'))))
				{
					MessageBox.Show("Not for you!");
					return;
				}
				if (num4 - 5 < 0)
				{
					num6 = 0;
				}
				else
				{
					num4 -= 5;
					num5++;
				}
			}
			int num7 = 1;
			num4 = 1;
			num5 = 0;
			if (num4 > length - 1)
			{
				MessageBox.Show("Not for you!");
				return;
			}
			while (num7 == 1)
			{
				if (!this.supplier.Text[num4].Equals(Form.ActiveForm.Text[num5 * 2]))
				{
					MessageBox.Show("Not for you!");
					return;
				}
				if (!this.supplier.Text[num4 + 1].Equals(Form.ActiveForm.Text[num5 * 2 + 1]))
				{
					MessageBox.Show("Not for you!");
					return;
				}
				if (num4 + 5 > length - 1)
				{
					num7 = 0;
				}
				else
				{
					num4 += 5;
					num5++;
				}
			}
			MessageBox.Show("Here is your star!\nECTF{" + this.supplier.Text + "}", base.Name = "Success!");
		}

		// Token: 0x06000007 RID: 7 RVA: 0x00002065 File Offset: 0x00000265
		private void heyhey(object sender, EventArgs e)
		{
			this.nantendoShadowBan();
		}

		// Token: 0x06000008 RID: 8 RVA: 0x0000206D File Offset: 0x0000026D
		protected override void Dispose(bool disposing)
		{
			if (disposing && this.components != null)
			{
				this.components.Dispose();
			}
			base.Dispose(disposing);
		}

		// Token: 0x06000009 RID: 9 RVA: 0x00002A8C File Offset: 0x00000C8C
		private void InitializeComponent()
		{
			this.supplier = new TextBox();
			this.checker = new Button();
			this.ichi = new Label();
			this.ni = new Label();
			base.SuspendLayout();
			this.supplier.Location = new Point(29, 31);
			this.supplier.Name = "supplier";
			this.supplier.Size = new Size(555, 22);
			this.supplier.TabIndex = 0;
			this.checker.Location = new Point(210, 70);
			this.checker.Name = "checker";
			this.checker.Size = new Size(191, 33);
			this.checker.TabIndex = 1;
			this.checker.Text = "Grab your star!";
			this.checker.UseVisualStyleBackColor = true;
			this.checker.Click += this.checker_Click;
			this.ichi.AutoSize = true;
			this.ichi.BackColor = Color.Transparent;
			this.ichi.Location = new Point(602, 90);
			this.ichi.Name = "ichi";
			this.ichi.Size = new Size(105, 16);
			this.ichi.TabIndex = 2;
			this.ichi.Text = "ZWpkaGtpYWIK";
			this.ichi.Visible = false;
			this.ni.AutoSize = true;
			this.ni.BackColor = Color.Transparent;
			this.ni.Location = new Point(602, 70);
			this.ni.Name = "ni";
			this.ni.Size = new Size(99, 16);
			this.ni.TabIndex = 3;
			this.ni.Text = "cnRwdnh1encK";
			this.ni.Visible = false;
			base.AutoScaleDimensions = new SizeF(8f, 16f);
			base.AutoScaleMode = AutoScaleMode.Font;
			base.ClientSize = new Size(609, 115);
			base.Controls.Add(this.ni);
			base.Controls.Add(this.ichi);
			base.Controls.Add(this.checker);
			base.Controls.Add(this.supplier);
			base.Name = "Form1";
			this.Text = "Mario star grabber";
			base.Load += this.heyhey;
			base.ResumeLayout(false);
			base.PerformLayout();
		}

		// Token: 0x04000001 RID: 1
		private IContainer components;

		// Token: 0x04000002 RID: 2
		private TextBox supplier;

		// Token: 0x04000003 RID: 3
		private Button checker;

		// Token: 0x04000004 RID: 4
		private Label ichi;

		// Token: 0x04000005 RID: 5
		private Label ni;
	}
}
