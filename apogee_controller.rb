class Portal::ApogeeController < PortalController
  # Hide the portal from roamers
  before_action :roaming_account_group_redirect, except: [:login_success]

  # Strip important params that tend to have trailing garbage
  before_action :strip_params

  # **************************************************************************
  # Protected methods for filters, helpers, and other customization.
  # **************************************************************************
  protected

  # Hardcoded configuration names. These are methods instead of constants in case
  # we ever end up overriding them in a superclass, where we have some common
  # behavior baked into a shared controller or module.
  def basic_usage_plan_name;      'Basic Usage Plan'      end
  def guest_usage_plan_name;      'Guest Usage Plan'      end
  def roaming_account_group_name; 'Roaming Account Group' end
  helper_method :basic_usage_plan_name, :guest_usage_plan_name, :roaming_account_group_name

  # Strip important params that may still have trailing garbage from bad forms. Prevents record
  # validation errors.
 

  # remove the # infront of the two lines below this to enable the controller mod
  # that allows you to view the page without a transient membership (for testing)
  def quarantine_trigger

  end
  
  def strip_params
    # Check top-level and common nested params
    [ nil,
      :account,
      :current_account,
      :payment_method,
    ].each do |form_key|
      form_params = form_key.nil? ? params : params[form_key]
      next unless form_params
      # Strip common fields
      %w(
        email
        email_confirmation
        first_name
        last_name
        login
        login_static
        mac
        password
        password_confirmation
        password_confirmation_static
        password_static
        pre_shared_key
        token
        username
      ).map(&:to_sym).each do |field_key|
        form_params[field_key].strip! if form_params[field_key].is_a?(String)
      end
    end
  end

  # Extend default portal instance variables
  def set_instance_variables
    # We still want all the normal default portal variables
    super

    # Make custom data key instances available in all views
    get_data_keys

    # Detect MAC randomization
    client_mac_private
  end

  # The instance variables that we map a SAML response to.
  def saml_instance_vars
    %w(
      first_name
      last_name
      username
      department
      on_campus_housing
    )
  end

  # Generate a random MAC for testing via the WAN
  def client_mac
    @client_mac ||= begin
      mac = super
      if mac.blank? && Rails.env.development?
        # Generate a fake "private MAC" based on the IP address
        mac = sprintf('92:b1:%02x:%02x:%02x:%02x', *client_ip.split(/\./))
      end
      mac
    end
  end

  # Check if the MAC is "private" (e.g. iOS)
  def client_mac_private
    # Look at the second character in a MAC address, if it is a 2, 6, A, or E it is a randomized
    # address.
    # https://www.mist.com/get-to-know-mac-address-randomization-in-2020/
    @client_mac_private = %w( 2 6 a e ).include?(client_mac.to_s.downcase[1])
  end

  # The name of the Custom Data Set used to configure the behavior in this
  # controller.
  def custom_data_set_name
    # This is simply the downcased name of the controller
    self.controller_name.downcase
  end

  # A CustomDataSet to configure the behavior in this custom portal
  def custom_data_set
    @custom_data_set ||= CustomDataSet.where(name: custom_data_set_name).first
  end

  # Get a key/value hash of our custom keys.
  def custom_data_keys
    @custom_data_keys ||= self.custom_data_set.try(:keys_hash)
  end

  # Note that custom_data_set() and friends are memoized to reduce
  # queries/performance

  # Iterate a list of Custom Data Keys configured for this portal, setting an instance variable named
  # after each.
  def get_data_keys
    custom_data_keys.each do |data_key_name, data_key_value|
      instance_variable_name = sprintf('data_key_%s', data_key_name.downcase.gsub(/\W/, '_'))
      logger.debug "@#{instance_variable_name} = #{data_key_value}"
      instance_variable_set("@#{instance_variable_name}", data_key_value)
    end
  end

  # The deployment named defined by a data key. This is used frequently, so make
  # it a special helper method.
  def rxg_name
    custom_data_keys['Rxg Name'] || sprintf('%s Rxg Name undefined', custom_data_set_name)
  end
  helper_method :rxg_name

  # ================================================================================================
  # Student PMS Functions
  # ================================================================================================

  # The URL containing the PMS student data. nil if this function is disabled.
  def pms_students_url
    custom_data_keys['PMS Students URL'].to_s.strip.presence
  end

  # How long until we refresh the PMS cache
  # TODO: Use a CustomDataKey?
  def pms_students_cache_life
    # Refresh more frequently in dev mode in case a new file is uploaded
    Rails.env.development? ? 1.minute : 1.hours
  end

  # Return a cache of the fetched PMS students
  def pms_students
    # Bailout unless the URL is configured in a custom data key
    return {} if pms_students_url.blank?

    # Include the URL in the cache key such that a change in the filename yields a cache refresh
    @pms_students ||= Rails.cache.fetch("#{custom_data_set_name}/pms_students/#{pms_students_url.to_sym}",
      expires_in: pms_students_cache_life
    ) do
      fetch_pms_students
    end
  end

  # Fetch a list of students emails containing their buildings and rooms
  #
  # ************************************************************************************************
  #
  # We will source this from a URL (e.g. Dropbox) configured in a custom data key. It is assumed that
  # the URL contains some kind of authentication token as to not be available to the public Internet.
  #
  # ************************************************************************************************
  # Custom Data Key name: "PMS Students URL"
  # Example URL value: https://www.dropbox.com/s/15wx2u9v8ejwiaj/Apogee%20Rooms.csv
  #
  # The CSV is assumed to include a headers line as the first row. We attempt to normalize header
  # keys keys to support different schools and formats. The order of the columns is irrelevant.
  #
  # ************************************************************************************************
  #
  # Debugging with rails console/runner:
  #
  #    rails runner "puts Portal::ApogeeController.new.send(:fetch_pms_students).to_yaml"
  #
  # Example output converted to YAML:
  #
  # praduyt01@ku.edu:
  #   :email: praduyt01@ku.edu
  #   :building: LEW
  #   :room: LEW-421
  # hadley_n_abbas@ku.edu:
  #   :email: hadley_n_abbas@ku.edu
  #   :building: JTC
  #   :room: JTC-411
  # ...
  #
  def fetch_pms_students
    # Bailout unless the URL is configured in a custom data key
    return {} if pms_students_url.blank?

    # Make sure we have a valid URL and use URI from here on out
    uri = URI::parse(pms_students_url)

    # Dropbox links must include the raw param, else we get a fancy UI. Don't assume the operator has
    # included this when copying a URL share from Dropbox.
    #
    # e.g. https://www.dropbox.com/s/15wx2u9v8ejwiaj/Apogee%20Rooms.csv?raw=1
    if uri.host.include?('dropbox.com')
      # Add a "raw" param if it doesn't already exist
      params = URI.decode_www_form(uri.query.to_s).to_h
      params.merge!('raw' => '1')
      uri.query = URI.encode_www_form(params.to_a)
    end

    # Download and parse the CSV, leveraging open-uri to fetch.
    logger.info "#{self.controller_name} portal - PMS: fetching CSV from #{uri}"
    begin
      CSV.new(URI.open(uri.to_s),
        # Assume we have headers included in the first row
        headers: true,
        # We don't always know the newline (windows or *nix?) and there could be blank data lines.
        row_sep: :auto, skip_blanks: true,
        # DO NOT use integer or datetime converters. This will mutate certain valid room
        # numbers (e.g. "0411")
        converters: nil,
        # Normalize header keys to support different schools and formats
        # Actual example/sample header:
        #   Student KU Email,Housing Building Name,Room #
        header_converters: lambda { |h|
          case h.downcase
          when /email|login/
            :email
          when /building|bldg/
            :building
          when /room|number/
            :room
          else
            h.to_sym
          end
        }
      # Return a Hash of students hashes keyed by email, omiting blank columns
      ).map { |row| [ row[:email], row.to_hash.compact ] }.to_h
    rescue => e
      logger.error "#{e.class} #{e.message}"
      flash[:exception] = "#{e.class}: #{e.message}"
    end
  end

  # List the configured building names
  #
  # **************************************************************************
  # BUILDING DROPDOWN CUSTOMIZATION (old way)
  #
  # The Building dropdown list shown on _account_form.erb and
  # _validated_account_form.erb comes from the custom portal note field
  # shown on the custom portal edit screen. List building names separated by a pipe.
  # If there is just one building, list it without a pipe.
  # If there is a formatting error, the building list will show as empty.
  #
  # Examples:
  # Building 1|Building 2|Building 3
  # Building 1
  # **************************************************************************
  #
  # The new way is to get the list from a CSV that we fetch
  def buildings_names_list
    # Memoize the list for the request
    @buildings_names_list ||= begin
      if pms_students_url
        # We should have fetched the list of buildings
        pms_students.values.map { |h| h[:building] }.uniq.compact.sort
      else
        # Fallback to the list being serialized within the CustomPortal
        self.custom_portal.note.to_s.split(/\s*\|\s*/)
      end
    end
  end
  # Make this list available throughout the views
  helper_method :buildings_names_list


  # **************************************************************************
  # Combined drop-down for builing and room from PmsServer>PmsRooms
  #  format is  building-room  <address1>-<address2>
  # **************************************************************************
  def pms_server_names_list
    # Memoize the list for the request
    @pms_server_names_list ||= begin
      if PmsServer.exists?
        PmsServer.first.pms_rooms.select(:room).map(&:room).uniq.sort
      else
        # Fallback to the list being serialized within the CustomPortal
        self.custom_portal.note.to_s.split(/\s*\|\s*/)
      end
    end
  end
  # Make this list available throughout the views
  helper_method :pms_server_names_list


  # We may need a PmsServer to exist to toggle certain backend functions in the rxg (e.g. RADIUS
  # auth + per-Room VTA).
  def pms_server
    # Only one server can be configured
    @pms_server ||= begin
      PmsServer.first ||
      # Just create one here if it's missing
      PmsServer.create!(
        name: sprintf('%s Student PMS', self.portal_name.camelize),
        note: sprintf('Created by %s Portal - nonfunctional', self.portal_name.camelize),
        # RG Nets custom API might be the least intrusive and possibly useable one day
        interface: 'Rgnets',
        # In theory we could implement the Rgnets PMS protocol. This does not actually exist but must
        # be configured.
        soap_endpoint: sprintf('https://%s/%s/pms_endpoint', DOMAIN_NAME, self.portal_path),
        soap_username: self.portal_name,
        # NOOP params
        protocol: 'IP', host: '127.0.0.1', port: '80',
        # Timeout fast since this does not exist
        timeout: 1,
        # Might be useful one day to share rooms?
        account_sharing: 'room',
        # rXg Defaults that the model does not fallback to
        ct_format: %w( dhcp_hostname mac_vendor usage_plan ),
        ct_length: 40,
        dd_format: %w( mac_decimal ),
        dd_length: 20,
        subsequent_transaction_max_count: 0,
        subsequent_transaction_max_lifetime: 0,
        subsequent_transaction_max_lifetime_unit: 'minutes',
        subsequent_transaction_price_reduction: '0%',
      )
    end
  end

  # Create Pms* objects and Account relations for a given student email + building/room combo
  def sync_pms_student(
    room:        nil,
    building:    nil,
    room_number: nil,
    email:       nil,
    account:     nil
  )
    # Is this feature enabled?
    return unless @data_key_pms_building_room_number || pms_students_url

    # logger.debug("email: #{email} room: #{room} building: #{building} room_number: #{room_number}")

    # Must have at least a room to continue.
    if building.present? && room.present? && room.to_s.include?(building)
      # The supplied "building" from the CSV is duplicated in the "room" field.
      # e.g. building: "AMI" room: "AMI-002"
      building, room_number = room.to_s.split('-')
    elsif building.present? && room.present?
      # "room" DOES NOT include the "building", assume it's just the room number.
      room_number = room
      room = [building, room_number].join("-")
    elsif room.present?
      # If room number OR building are still blank, assume they are concatenated
      # together.
      building, room_number = room.to_s.split('-')
    end
    return if room.blank?

    # Somehow we at least also need an email address:
    #
    # An Account is optional. The caller might want to pass in a non-persisted instance. If we end up
    # not finding an Account, it means the student has yet to sign in. But we can still go about
    # creating a PmsRoom, which may be useful to see in the UI.
    account ||= Account.find_by_email(email) || Account.find_by_login(email)
    # Don't need an email if we were already given an account
    email ||= account.try(:email)

    # Get or build the room.
    pms_room = pms_server.pms_rooms.find_or_create_by!(room: room)

    # Need email and first/last name
    if email
      # We may not really need a PmsGuest, but may as well create one in case it is useful for some
      # kind of per-Guest VLAN implementation.
      pms_guest = pms_server.pms_guests.create_with(
        # Initialize with a reasonable name drived from the email until we have an Account with more
        # info
        # TODO: We could probably have the name added to the CSV
        name: email.sub(/@.*$/, ''),
        # Shouldn't matter, but be sure we never try and post a charge to something
        no_post: true,
      ).find_or_create_by!(email_address: email)

      # A Guest should probably belong to only one Room
      pms_guest.pms_rooms = [ pms_room ] unless pms_guest.pms_rooms.include?(pms_room)

      # If we have an Account, we can add info to the PmsGuest and associate everything to it.
      if account
        # Update the guest with the correct name and any other info that may become relevant.
        pms_guest.update!(
          first_name: account.first_name,
          name: account.last_name,
        )
        # Associate everything with the right Account. An Account should belong to only one Room and
        # Guest.
        account.pms_rooms  = [ pms_room  ] unless account.pms_rooms.include?(pms_room)
        account.pms_guests = [ pms_guest ] unless account.pms_guests.include?(pms_guest)

        # Historically we also store this info the Account address fields.
        account.address1 = building
        account.address2 = room_number
        # Don't blowup if somehow the Account was already invalid?
        begin
          account.save! if account.changed?
        rescue ActiveRecord::RecordInvalid => e
          logger.error "Error saving Account #{account.login} with PMS info - #{e.class.to_s}: #{e.message}"
        end
      end
    end

  end

  # Import PMS entities from the configured CSV URL. This is essentially a ghetto polling-based PMS
  # sync interface.
  #
  # We want to run this on a regular basis via a scheduled job of some kind, which facilitates the
  # school moving a student to another room.
  def import_pms_students
    # Don't read from the cache because the rXg rails file caching mechanism could yield to a
    # background process (e.g. CustomEmail/delayed_job) using root perms to write the cache file,
    # which may not be readable by the web server processes.
    fetch_pms_students.each do |email, student|
      logger.info "#{self.controller_name} portal - PMS: importing student: #{student[:email]}"
      sync_pms_student(
        room:  student[:room],
        building: student[:building],
        email: student[:email],
      )
    end
    # Return the students info that we fetched and imported, which might be useful to use in a
    # CustomEmail or what not.
  end

  # ================================================================================================
  # End Student PMS Functions
  # ================================================================================================

  # Map a Department to a configured UsagePlan
  #
  # **************************************************************************
  # DEPARTMENT => USAGE PLAN MAPPING
  #
  # The UsagePlan for a Department is configured by populating the note field in
  # the UsagePlan with a string like "department: DepartmentName". Otherwise we
  # fallback to the Basic plan. This plan is applied after a SAML login.
  #
  # **************************************************************************
  # TODO: Something with custom data keys - Can we use the policies association?
  def usage_plan_for_department(department)
    # Find one for the department, or fallback to the basic plan.
    unless department.blank?
      chosen_usage_plan = UsagePlan.where("note ILIKE '%department: #{department.downcase.strip}%'").first
    end
    chosen_usage_plan ||= UsagePlan.where(name: basic_usage_plan_name).first

    logger.debug "usage_plan_for_department #{department}: #{chosen_usage_plan.try(:name)}"
    return chosen_usage_plan
  end

  # Where this CustomPortal lives on the filesystem
  def portal_dir
    File.join(PORTALS_DIR, self.controller_name.downcase)
  end

  # **************************************************************************
  # Public action overrides and customization.
  # **************************************************************************
  public

  # Render git version info for this custom portal
  def version
    render html: [
      `git -C #{portal_dir} log -1 --format="%H"`,
      `git -C #{portal_dir} log -1 --format="%ad"`
    ].join("<br/>").html_safe
  end

  # A custom view with quick_purchase behavior
  def guest_user_sign_up
    quick_purchase
  end
  def guest_user_quick_purchase_charge
    # Force a random login/account name and password
    params[:login_static] = sprintf('guest_account_%024i',
      rand(10000000000..100000000000000000000000000))
    params[:password_static] = params[:password_confirmation_static] = SecureRandom.urlsafe_base64(16)

    # Override the normal quick_purchase plan behavior and force a "Guest" selection.
    if guest_plan = UsagePlan.find_by_name(guest_usage_plan_name)
      @usage_plan = guest_plan

      # Must reset the Subscription (@subscription) which was already set via the
      # subscription_from_params before_action.
      subscription_from_params
    else
      flash[:notice] = "Failed to find a '#{guest_usage_plan_name}' configured"
      logger.warn "Failed to find a '#{guest_usage_plan_name}' configured"
    end

    # Do the normal quick_purchase behavior
    quick_purchase_charge
  end

  # Anoter custom view with quick_purchase behavior.
  def new_user_sign_up
    quick_purchase
  end
  def new_user_quick_purchase_charge

    # if account already exists with email.
    if Account.exists?(email: params[:email])
      flash[:notice] = "Email already used!"
      redirect_to_back_or_index
      return
    end

    params[:login_static]   = params[:email]           if @data_key_email_login_mapping
    params[:pre_shared_key] = params[:password_static] if @data_key_password_psk_mapping

    quick_purchase_charge

    # We may have been given the student's room/building info to store in our local PMS.
    if (@data_key_pms_room_mapping)
      sync_pms_student(
        account:     current_account,
        room: params["payment_method"]["address2"].strip,
      )
    else
      sync_pms_student(
        account:     current_account,
        building:    params["payment_method"]["address1"].strip,
        room_number: params["payment_method"]["address2"].strip,
      )
    end
  end

  JWT_ALG    = 'HS256'.freeze
  JWT_SECRET = Rails.application.try(:secret_key_base) || Rails.application.config.try(:secret_key_base)

  # The portal end-user may request an Account owner to remove her MAC address from another Account.
  def request_device_release
    # Need an email to send the confirmation to
    email = params[:email].to_s.strip
    if email.blank?
      flash[:notice] = "Must provide an email address"
      redirect_to_back_or_index
      return
    end

    # Need an account and MAC to send the request to/for
    mac = params[:mac].to_s.strip.presence || client_mac
    existing_account = Account.find_by_mac(mac)
    unless existing_account
      flash[:notice] = "Current device MAC does not have an existing account"
      redirect_to_back_or_index
      return
    end

    # Need a Device too
    existing_device = existing_account.devices.find_by_mac(mac)
    unless existing_device
      flash[:notice] = "Current device MAC does not have an existing device stored"
      redirect_to_back_or_index
      return
    end

    # Generate a secure token with an unlink URL and send it to the account owner.
    # Include params necessary to remove the device and email the requesting user.
    jwt_payload = {
      account_id: existing_account.id,
      mac: mac,
      email: email,
      exp: 2.days.from_now.to_i # JWT expiration
    }
    token = JWT.encode(jwt_payload, JWT_SECRET, JWT_ALG)
    link = helpers.url_for(action: :device_release, token: token, only_path: false)
    logger.debug("Generated release_existing_device link: #{link} #{jwt_payload.to_yaml}")

    # Send an Email to the Account owner
    # This must be a temporary (non-persisted) CustomEmail, because there is not a way to insert the
    # URL and other Account info as object replacements.
    custom_email = CustomEmail.new(
      name: sprintf('%s Portal Request Device Release', self.portal_name.camelize),
      delivery_method: 'email',
      from: 'portal',
      subject: 'Device Release Request',
    )
    custom_email.body = <<EOF
Hello #{existing_account.login},
<br>
#{email} has requested that you release device #{existing_device.to_label} from your account.
<br>
Please #{helpers.link_to('Click Here', link)} if you would like to accept this request and unlink the device.
EOF
    custom_email.deliver_message(email: existing_account.email)

    flash[:message] = "A request for release was sent to the account owner"
    redirect_to action: :index
  end

  # Unlink (release) a Device from an Account. Requires a valid JWT sent by request_device_release,
  # such that someone can't delete arbitrary Devices without at least spoofing a MAC first.
  def device_release
    begin
      token = JWT.decode(params[:token], JWT_SECRET, JWT_ALG)
      payload = token.first
      logger.debug("Device release request: #{payload.to_yaml}")
      if device = Account.find_by_id(payload['account_id']).devices.find_by_mac(payload['mac'])
        email = payload['email']
        logger.info("Releasing Device #{device.to_label} from Account #{device.account.login} on behalf of #{email}")
        device.destroy

        # Send an email to the original requesting email
        # Make this a temporary (non-persisted) CustomEmail like the request.
        custom_email = CustomEmail.new(
          name: sprintf('%s Portal Accept Device Release', self.portal_name.camelize),
          delivery_method: 'email',
          from: 'portal',
          subject: 'Device Release Approved',
        )
        custom_email.body = <<EOF
Hello #{email},
<br>
#{device.account.login} has approved your request to release device #{device.to_label} from their account.
EOF
        custom_email.deliver_message(email: email)

        flash[:message] = "Successfully released device #{device.to_label}"
      else
        flash[:notice] = "Device to release was not found"
      end
    rescue => e
      logger.error "#{e.class} #{e.message}"
      flash[:exception] = "Device release failed - #{e.class}: #{e.message}"
      redirect_to action: :index
    end

    redirect_to action: :index unless performed?
  end

  # Authenticate against a RadiusRealm and create an Account if success.
  # TODO: Refactor against newer rXg behavior.
  def proxy_radius
    @debug = false
    if logged_in?
      flash[:notice] = :already_logged_in
      redirect_to_back_or_index
      return
    end
    # find the RadiusRealm indicated by the login form. the way the realm is
    # passed along may differ depending on deployment.
    rr = nil
    if params[:radius_realm]
      rr = RadiusRealm.find_by_id(params[:radius_realm][:id])
    elsif params[:realm]
      rr = RadiusRealm.find_by_name(params[:realm])
    else
      flash[:notice] = :improper_request
      redirect_to_back_or_index
      return
    end

    if rr
      # login paramater can differ depending on deployment (i.e., may be "username")
      login = (params[:login] || params[:username]).to_s.encode.strip
      password = params[:password].to_s.encode.strip

      # send the radius request
      begin
        radius_response, rrs = rr.radius_auth_acct_request(login, password,
                                                            client_ip, client_mac, new_radius_acct_session_id)
      rescue RadiusProtocolError => e
        logger.error "RadiusProtocolError: #{e.message}"
        flash[:exception] = "RadiusProtocolError: #{e.message}"
        redirect_to_back_or_index
        return
      end

      if radius_response.nil?
        # no servers were configured or none responded
        flash[:notice] = :no_remote_response
        redirect_to_back_or_index
      elsif radius_response.success?

        if @account = Account.find_by_login(params[:login]) # use existing_account?
          @account.password = password
          @account.password_confirmation = password
          @account.save!
        else
          #unless Account.find_by_login(params[:login]) # use existing_account?
          # No account exists for "student", we need to create one
          basic_plan = UsagePlan.first # probably need a consistent name or something else
          global_psk = "thecatchallpsk"
          RadiusServerAttribute.where(:name => 'Ruckus-DPSK').each do |rsa|
            next if rsa.value.match(/^%/) # skip non-global values
            global_psk = rsa.value
          end
          #ag = AccountGroup.find_by_name('Student')
          @account = Account.new(
            :login => params[:login],
            :password => params[:password], :password_confirmation => params[:password],
            :first_name => params[:login],
            :last_name => params[:login],
            :email => params[:login],
            :usage_plan => basic_plan,
            :do_apply_usage_plan => true,
            # set account PSK to the global PSK so they can still login and change their key if desired
            :pre_shared_key => global_psk,
            :note => 'automatically created for student login'
          )
          #@account.account_groups = [ ag ]
          #TODO: catch exceptions
          @account.save!
        end

        account_login

      else
        # Access-Reject or otherwise - the credentials were invalid
        flash[:notice] = :invalid_credentials
        # Add the RADIUS reply message to flash variable so it can be displayed
        # to the end-user, or returned to a remote portal for display.
        if reply_message_attributes = radius_response['Reply-Message']
          message = reply_message_attributes.first
          flash[:message] = message unless message.blank?
        end
        redirect_to_back_or_index
      end
    else
      # someone or something tried to use an invalid RadiusRealm
      flash[:notice] = :invalid_radius_request
      redirect_to_back_or_index
    end
  end

  # The special roaming group which redirects users to a view telling them to go
  # home.
  def roaming_account_group_redirect
    if self.group.try(:name) == roaming_account_group_name
      render :roaming_account_group
      return true
    end
  end

  # Permit the user to edit their Account after SAML or LDAP auth, using info
  # from the OmniauthProfile (SAML) or LDAP search.
  def student_profile_update
    # We should always have current_account params from the form
    unless @current_account_params = params[:current_account]
      flash[:notice] = :improper_request
      redirect_to_back_or_index
      return
    end

    # The omniauth profile session only exists for the SAML behavior and not LDAP.
    if session[:omniauth_profile_id]
      omniauth_profile = OmniauthProfile.find_by_id(session[:omniauth_profile_id])
      unless omniauth_profile
        flash[:notice] = :improper_request
        redirect_to_back_or_index
        return
      end
      @current_account = omniauth_profile.account
    elsif session[:ldap_account_id]
      @current_account = Account.find_by_id(session[:ldap_account_id])
    end

    # We should have found an account above
    unless @current_account
      flash[:notice] = :improper_request
      redirect_to_back_or_index
      return
    end

    # If we get here the request looks good. Update the Account.
    if @current_account.update(
      pre_shared_key: @current_account_params['pre_shared_key'].strip,
      phone: @current_account_params['phone'].strip,
    )
      # We may have been given the student's room/building info to store in our local PMS.
      if (@data_key_pms_room_mapping)
        sync_pms_student(
          account:     @current_account,
          room: @current_account_params['address2'].strip,
        )
      else
        sync_pms_student(
          account:     @current_account,
          building:    @current_account_params['address1'].strip,
          room_number: @current_account_params['address2'].strip,
        )
      end

      # Login the new student account after they have updated their profile
      self.login_session = login_session_for_account(
        @current_account,
        doing_portal_automatic_login = false,
        omniauth_profile
      )
      flash.now[:message] = "Account updated successfully"

      # Delete SAML and LDAP Account tracking
      session.delete(:omniauth_profile_id)
      session.delete(:ldap_account_id)

      redirect_to action: :login_success
      return
    else
      flash.now[:message] = "Error: Account not saved"
      render :student_edit_profile
      return
    end
  end

  # A custom callback_path for apogee SAML provider. This is where we do the
  # fancy mapping of SAML data into instance variables based on custom data keys.
  def saml_success
    unless omniauth_strategy && omniauth_profile
      flash[:notice] = :no_omniauth_strategy
      redirect_to action: :index
      return
    end

    # logger.debug "----------------------------------------------------------------------------"
    # logger.debug "----------------------- #{request} ------------------------------"
    # logger.debug "----------------------- #{request.inspect} ------------------------------"
    # logger.debug "----------------------- #{request.env.inspect} ------------------------------"
    # logger.debug "----------------------- #{request.env['omniauth.auth'].inspect} ------------------------------"
    # logger.debug "----------------------- #{request.env['omniauth.auth']['extra'].inspect} ------------------------------"
    # logger.debug "----------------------- #{request.env['omniauth.auth']['extra']['raw_info'].inspect} ------------------------------"
    # logger.debug "----------------------------------------------------------------------------"

    # Get the hash we care about
    raw_info = request.env['omniauth.auth']['extra']['raw_info'].attributes.map { |k,v| [ k, v.try(:first) ] }.to_h
    logger.debug "SAML raw_info"
    logger.debug raw_info.to_yaml

    # Configure behavior with a custom data key. Use the top-level data set name
    # as a namespace.
    saml_cds = CustomDataSet.find_or_create_by(name: sprintf('%s-%s-map',
      custom_data_set_name, omniauth_strategy.try(:name)|| 'SAML').downcase)

    # Store the last response for debugging via UI and easily being able to set
    # key mapping.
    raw_cdk = saml_cds.custom_data_keys.find_or_initialize_by(name: '_last_raw_info')
    raw_cdk.value_text = raw_info.map { |k,v| "#{k}: #{v}" }.join("\n\n")
    raw_cdk.save!

    # The strategy where the CustomDataKey is keyed by the instance variable name
    #
    # saml_instance_vars.each do |var|
    #   # Create a CustomDataKey if it's missing (first time?)
    #   cdk = saml_cds.custom_data_keys.find_or_create_by(name: var)
    #
    #   # Fallback to the literal name if blank/new
    #   unless cdk.values.any?
    #     cdk.update!(
    #       value_string: var,
    #       note: "Map SAML key Name to portal variable Key",
    #     )
    #   end
    #
    #   # Get the SAML field value using the mapping. The CustomDataKey has a name
    #   # "matching" the @instance, and the value_string is desired key in the SAML
    #   # response.
    #   saml_key   = cdk.value_string
    #   saml_value = raw_info[saml_key]
    #   logger.debug "SAML map \"#{saml_key}\" -> \"#{var}\""
    #
    #   # Set the actual instance var based on the mapping
    #   if saml_value.to_s.downcase == 'true'
    #     # Support booleans like @on_campus_housing
    #     instance_variable_set("@#{var}", true)
    #   elsif saml_value.to_s.downcase == 'false'
    #     instance_variable_set("@#{var}", false)
    #   else
    #     instance_variable_set("@#{var}", saml_value)
    #   end
    # end

    # The alternate strategy where the CustomDataKey is keyed by the SAML key name
    raw_info.each do |saml_key, saml_value|

      # Create a CustomDataKey if it's missing (first time?)
      cdk = saml_cds.custom_data_keys.find_or_initialize_by(name: saml_key)
      if cdk.new_record?
        cdk.note = <<-EOF
Map SAML \"#{saml_key}\" to portal variable named after the Value String.

Example Data: #{saml_value}

Possible variables (Value String):
#{saml_instance_vars.join("\n")}
EOF

        # Start with some well-known mappings
        cdk.value_string = 'first_name' if saml_key == 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'
        cdk.value_string = 'last_name'  if saml_key == 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'
        cdk.value_string = 'username'   if %w(
          name
          email
          sAMAccountName
          http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
          http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name
        ).include?(saml_key)
        # If the SAML key is identical to a desired instance, use it if the above
        # cases failed.
        cdk.value_string ||= saml_key.downcase if saml_instance_vars.include?(saml_key.downcase)

        # Only save new keys, after that we rely on the operator to get it right
        cdk.save!

        # Raise a warning about a new key that possibly needs mapping
        HealthNotice.portal_log_warn("New #{saml_cds.name{}} key encountered: #{saml_key}")
      end

      # Can't do anything without a mapping
      var = cdk.value_string
      next if var.blank?

      # Normalize @username to match Account login requirements
      if var == 'username'
        saml_value = saml_value.downcase unless saml_value.blank?
      end

      # Get the SAML field value using the mapping.
      logger.debug "SAML map \"#{saml_key}\" -> \"#{var}\""

      # Set the actual instance var based on the mapping
      if saml_value.to_s.downcase == 'true'
        # Support booleans like @on_campus_housing
        instance_variable_set("@#{var}", true)
      elsif saml_value.to_s.downcase == 'false'
        instance_variable_set("@#{var}", false)
      else
        instance_variable_set("@#{var}", saml_value)
      end
    end

    # Log what we decided to use
    saml_instance_vars.each do |var|
      logger.debug "SAML var @#{var} = " + instance_variable_get("@#{var}").to_s
    end

    # A special bailout when on campus housing is false
    if @on_campus_housing == false
      flash[:notice] = :invalid_student_housing_credentials
      redirect_to :action => :index
      return
    end

    # The default portal behavior of calling omniauth_success...

    # Run our override for omniauth_success, bailing out if there was a redirect
    # already. This is basically
    omniauth_success; return if performed?

    # The normal behavior for existing Accounts, where we go straight to login
    # success
    redirect_to action: :login_success
  end

  # Override default portal omniauth_login to workaround rxg bug:
  # NoMethodError: undefined method `find_by' for []:Array:
  # ["/space/rxg/console/app/controllers/portal_controller.rb:450:in
  # #`omniauth_login'",
  # "/space/rxg/console/app/controllers/portal_controller.rb:566:in `saml_login'",
  # ...
  def omniauth_login(provider_type)
    begin
      super(provider_type)
    rescue => e
      # Assume PortalController bug and return no match
      logger.error "#{e.class.to_s}: #{e.message}"
      flash[:notice] = :no_matching_strategies
      redirect_to_back_or_index
    end
  end

  # Override the SAML/OmniAuth login behavior.
  #
  # This should be similar to the LDAP login behavior (ldap_login).
  def omniauth_success
    unless omniauth_strategy && omniauth_profile
      flash[:notice] = :no_omniauth_strategy
      redirect_to action: :index
      return
    end

    # Track the omniauth_profile through to student_profile_update()
    session[:omniauth_profile_id] = omniauth_profile.id

    omniauth_profile.email      ||= @username
    omniauth_profile.first_name ||= @first_name
    omniauth_profile.last_name  ||= @last_name

    # Instantiate a student Account using the SAML profile
    begin
      @account = Account.find_or_create_from_omniauth_profile(omniauth_profile)
    rescue ActiveRecord::RecordInvalid => e
      # Workaround a bug in rXg Account.find_or_create_from_omniauth_profile if
      # a student changes their email address to that of an existing Account
      # having the same login.
      logger.error "Error creating Account from profile - #{e.class.to_s}: #{e.message}"
    end
    # Fallback to an existing account if the above fails
    @account ||= Account.find_by_login(@username) ||
                 Account.find_by_email(omniauth_profile.email.to_s.downcase) ||
                 Account.find_by_login(omniauth_profile.email.to_s.downcase)
    # Should not get here without an Account...

    # Render student_edit_profile if it's a new Account. Check for a nil
    # logged_in_at (never logged in before) because it's too late here for
    # id_changed? or new_record?.
    if @account.logged_in_at.nil?

      # Apply a plan for new Accounts only
      if chosen_usage_plan = usage_plan_for_department(@department)
        @account.apply_usage_plan(chosen_usage_plan)
      else
        raise "Department Usage Plan Error"
      end

      # Force a profile update
      @current_account = @account

      # Attempt to fetch the student from the PMS (CSV file cache) and Update the Account's PMS
      # relations if available.
      if student_hash = pms_students[@current_account.email]
        sync_pms_student(
          account: @current_account,
          room:    student_hash[:room],
        )
      end

      # Hide the "default" generated key, only in the form, so the user must
      # enter a new one. This must happen after applying the plan or any other
      # save.
      @current_account.pre_shared_key = ''

      render :student_edit_profile
    else
      # Login the existing Account
      self.login_session = login_session_for_account(@account, doing_portal_automatic_login = false, omniauth_profile)
      redirect_to action: :login_success
    end
  end

  # Override the usual ldap_login in order to force a student to update her
  # Account info before creating a LoginSession.
  #
  # This should be similar to the SAML login behavior (omniauth_success).
  def ldap_login
    unless params[:ldap_domain] && params[:login].present? && params[:password].present?
      flash[:notice] = :improper_request
      redirect_to_back_or_index
      return
    end

    if logged_in?
      flash[:notice] = :already_logged_in
      redirect_to_back_or_index
      return
    end

    if ld = LdapDomain.find_by_id(params[:ldap_domain][:id])
      login = params[:login].to_s.encode.strip
      password = params[:password].to_s.encode.strip
      begin
        if lds = ld.authenticate(login, password)
          # LDAP bind success - login the end-user

          if ld.create_account?
            @account = ld.account_for_username(login, password)
            new_record = @account.new_record?
            if @account.save
              # ================================================================
              # = Branch ldap_login behavior from the DefaultPortal =
              # ================================================================
              if new_record # new Account
                # DO NOT create a LoginSession yet

                # Track the account we just created
                session[:ldap_account_id] = @account.id

                # Apply a usage plan if the normal group<=>plan matching logic
                # didn't work.
                unless @account.usage_plan
                  # Apply a plan for new Accounts only
                  #
                  # TODO: We don't yet have @department mapping for LDAP logins
                  # like we do with SAML (saml_instance_vars(), etc). Assume
                  # either the LdapDomain in the rXg is configured correctly to
                  # match a UsagePlan#name against an LDAP group, or only one
                  # plan is configured, or usage_plan_for_department() will
                  # fallback to the "basic" plan.
                  if chosen_usage_plan = usage_plan_for_department(@department)
                    @account.apply_usage_plan(chosen_usage_plan)
                  else
                    raise "Department Usage Plan Error"
                  end
                end

                # Force a profile update
                @current_account = @account

                # Attempt to fetch the student from the PMS (CSV file cache) and Update the Account's PMS
                # relations if available.
                if student_hash = pms_students[@current_account.email]
                  sync_pms_student(
                    account: @current_account,
                    room:    student_hash[:room],
                  )
                end

                # Hide the "default" generated key, only in the form, so the user
                # must enter a new one. This must happen after applying the plan
                # or any other save.
                @current_account.pre_shared_key = ''

                render :student_edit_profile
                return
              else
                # ==============================================================
                # = Resume default portal behavior =
                # ==============================================================
                # Existing accounts proceed to login success as usual
                self.login_session = login_session_for_account(@account)
              end

            else
              flash[:notice] = @account.errors.messages.to_a.join(' - ')
              redirect_to_back_or_index
              return
            end
          else

            # authenticate(), if successful, returns the LdapDomainServer that
            # returned the valid response, so we may later save this in the
            # LoginSession to instrument whether a primary, secondary, or
            # tertiary server was contacted
            ldap_login_session_new(ld, lds, login, password)

          end
          # end-user is now logged in
          flash[:notice] = :logged_in
          redirect_to :action => :login_success
        else
          # connection failed or invalid credentials
          flash[:notice] = :invalid_credentials
          redirect_to_back_or_index
        end
      rescue Net::LDAP::Error => e
        logger.error "#{e.class.to_s}: #{e.message}"
        flash[:exception] = "LDAP Error: #{e.message}"
        redirect_to_back_or_index
      end
    else
      # someone or something tried to use an invalid LdapDomain
      flash[:notice] = :invalid_ldap_request
      redirect_to_back_or_index
    end
  end

  # Extend default portal add_device to catch a locked MAC and offer the request to release it.
  def add_device
    begin
      super
    rescue ActiveRecord::RecordInvalid => e
      logger.error "#{e.class.to_s}: #{e.message}"
      flash[:exception] = "Add Device Error: #{e.message}"
      if e.message =~ /locked/
        redirect_to action: :release_existing_device, mac: params[:device_mac].to_s.strip
      else
        redirect_to_back_or_index
      end
    end
  end

end

