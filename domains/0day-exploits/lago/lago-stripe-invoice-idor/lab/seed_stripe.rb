# Seed Stripe providers + victim stripe_customer. Run inside the Lago API container.
# Args: attacker_org_id victim_org_id victim_customer_id webhook_secret
attacker_org_id, victim_org_id, victim_customer_id, webhook_secret = ARGV
raise "usage" if [attacker_org_id, victim_org_id, victim_customer_id, webhook_secret].any?(&:blank?)

[attacker_org_id, victim_org_id].each do |oid|
  org = Organization.find(oid)
  p = PaymentProviders::StripeProvider.find_or_initialize_by(organization_id: oid, code: "stripe_lab")
  p.name = "Stripe Lab"
  p.secret_key = "sk_test_lab_#{oid.delete("-")[0, 12]}"
  p.webhook_secret = webhook_secret
  p.save!
  puts "IOC stripe_provider org=#{oid} id=#{p.id}"
end

cust = Customer.find(victim_customer_id)
victim_provider = PaymentProviders::StripeProvider.find_by!(organization_id: victim_org_id, code: "stripe_lab")
cust.update!(payment_provider: "stripe", payment_provider_code: "stripe_lab")

sc = PaymentProviderCustomers::StripeCustomer.find_or_initialize_by(
  customer_id: cust.id,
  organization_id: victim_org_id
)
sc.payment_provider_id = victim_provider.id
sc.provider_customer_id = "cus_lab_victim"
sc.provider_payment_methods = ["card"]
sc.save!
puts "IOC stripe_customer id=#{sc.id} customer=#{cust.id}"
puts "IOC stripe-seeded"
