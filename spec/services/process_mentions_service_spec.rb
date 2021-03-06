require 'rails_helper'

RSpec.describe ProcessMentionsService, type: :service do
  let(:account)    { Fabricate(:account, username: 'alice') }
  let(:visibility) { :public }
  let(:status)     { Fabricate(:status, account: account, text: "Hello @#{remote_user.acct}", visibility: visibility) }

  subject { ProcessMentionsService.new }

  context 'OStatus with public toot' do
    let(:remote_user) { Fabricate(:account, username: 'remote_user', protocol: :ostatus, domain: 'example.com', salmon_url: 'http://salmon.example.com') }

    before do
      stub_request(:post, remote_user.salmon_url)
      subject.call(status)
    end

    it 'does not create a mention' do
      expect(remote_user.mentions.where(status: status).count).to eq 0
    end
  end

  context 'OStatus with private toot' do
    let(:visibility)  { :private }
    let(:remote_user) { Fabricate(:account, username: 'remote_user', protocol: :ostatus, domain: 'example.com', salmon_url: 'http://salmon.example.com') }

    before do
      stub_request(:post, remote_user.salmon_url)
      subject.call(status)
    end

    it 'does not create a mention' do
      expect(remote_user.mentions.where(status: status).count).to eq 0
    end

    it 'does not post to remote user\'s Salmon end point' do
      expect(a_request(:post, remote_user.salmon_url)).to_not have_been_made
    end
  end

  context 'ActivityPub' do
    context do
      let(:remote_user) { Fabricate(:account, username: 'remote_user', protocol: :activitypub, domain: 'example.com', inbox_url: 'http://example.com/inbox') }

      before do
        stub_request(:post, remote_user.inbox_url)
        subject.call(status)
      end

      it 'creates a mention' do
        expect(remote_user.mentions.where(status: status).count).to eq 1
      end

      it 'sends activity to the inbox' do
        expect(a_request(:post, remote_user.inbox_url)).to have_been_made.once
      end
    end

    context 'with an IDN domain' do
      let(:remote_user) { Fabricate(:account, username: 'sneak', protocol: :activitypub, domain: 'xn--hresiar-mxa.ch', inbox_url: 'http://example.com/inbox') }
      let(:status) { Fabricate(:status, account: account, text: "Hello @sneak@h??resiar.ch") }

      before do
        stub_request(:post, remote_user.inbox_url)
        subject.call(status)
      end

      it 'creates a mention' do
        expect(remote_user.mentions.where(status: status).count).to eq 1
      end

      it 'sends activity to the inbox' do
        expect(a_request(:post, remote_user.inbox_url)).to have_been_made.once
      end
    end
  end

  context 'Temporarily-unreachable ActivityPub user' do
    let(:remote_user) { Fabricate(:account, username: 'remote_user', protocol: :activitypub, domain: 'example.com', inbox_url: 'http://example.com/inbox', last_webfingered_at: nil) }

    before do
      stub_request(:get, "https://example.com/.well-known/host-meta").to_return(status: 404)
      stub_request(:get, "https://example.com/.well-known/webfinger?resource=acct:remote_user@example.com").to_return(status: 500)
      stub_request(:post, remote_user.inbox_url)
      subject.call(status)
    end

    it 'creates a mention' do
      expect(remote_user.mentions.where(status: status).count).to eq 1
    end

    it 'sends activity to the inbox' do
      expect(a_request(:post, remote_user.inbox_url)).to have_been_made.once
    end
  end
end
