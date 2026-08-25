/**
 * Telegram Alert Module
 * Sends security alerts to Telegram (only for BARK/danger events)
 */

import fetch from 'node-fetch';
import { createRequire } from 'module';

export class TelegramAlert {
  constructor(config) {
    this.enabled = config.telegram?.enabled ?? true;
    this.botToken = process.env.TELEGRAM_BOT_TOKEN;
    this.chatId = config.telegram?.chatId || process.env.TELEGRAM_CHAT_ID;
    
    if (this.enabled && !this.botToken) {
      console.warn('⚠️ Telegram alerts enabled but no TELEGRAM_BOT_TOKEN found');
      this.enabled = false;
    }
  }

  /**
   * Send alert for dangerous packages (BARK only)
   * @param {string} packageName - Package name
   * @param {Object} decision - Decision object
   * @returns {Promise<boolean>} Success status
   */
  async sendDangerAlert(packageName, decision) {
    if (!this.enabled) {
      return false;
    }

    if (decision.action !== 'BARK') {
      // Only send alerts for danger (BARK), not warnings (WHINE)
      return false;
    }

    let sharedSendMessage;
    try {
      const _require = createRequire(import.meta.url);
      const sharedMod = _require('../../shared/telegram-send.js');
      sharedSendMessage = sharedMod?.sendMessage;
    } catch (err) {
      console.warn(`⚠️ Telegram shared module unavailable: ${err.message}`);
      return false;
    }

    if (!sharedSendMessage) {
      console.warn('⚠️ Telegram shared sendMessage function unavailable');
      return false;
    }

    const message = this.formatAlertMessage(packageName, decision);

    try {
      const apiBase = `https://api.telegram.org/bot${this.botToken}`;
      await sharedSendMessage(apiBase, this.chatId, message, {
        agentId: 'guard-dog',
        messageType: 'alert',
        extraPayload: { disable_web_page_preview: true },
      });
      return true;
    } catch (error) {
      console.error('Failed to send Telegram alert:', error.message);
      return false;
    }
  }

  /**
   * Format alert message for Telegram
   * @param {string} packageName - Package name
   * @param {Object} decision - Decision object
   * @returns {string} Formatted message
   */
  formatAlertMessage(packageName, decision) {
    let message = `🚨 *GUARD DOG ALERT: DANGER DETECTED*\n\n`;
    message += `*Package:* \`${packageName}\`\n`;
    message += `*Threat Level:* ${decision.threat}\n`;
    message += `*Confidence:* ${decision.confidence}%\n\n`;
    
    if (decision.reasons.length > 0) {
      message += '*Reasons:*\n';
      decision.reasons.forEach(reason => {
        // Remove emoji for cleaner Markdown
        const cleanReason = reason.replace(/[🚨⚠️❌❓🆕📦👤⭐]/g, '').trim();
        message += `• ${cleanReason}\n`;
      });
    }

    // Add scan details if available
    if (decision.details?.scan?.maliciousVotes > 0) {
      message += `\n*VirusTotal:* ${decision.details.scan.maliciousVotes} malicious detections`;
    }

    message += `\n\n⏰ ${new Date().toISOString()}`;
    
    return message;
  }

  /**
   * Test telegram connection
   * @returns {Promise<boolean>} Success status
   */
  async testConnection() {
    if (!this.enabled) {
      return false;
    }

    try {
      const response = await fetch(
        `https://api.telegram.org/bot${this.botToken}/getMe`
      );
      
      if (!response.ok) {
        throw new Error('Bot token invalid');
      }

      const data = await response.json();
      console.log(`✅ Telegram bot connected: @${data.result.username}`);
      return true;
    } catch (error) {
      console.error('❌ Telegram connection failed:', error.message);
      return false;
    }
  }
}
